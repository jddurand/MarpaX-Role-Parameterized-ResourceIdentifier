use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier;

# ABSTRACT: MarpaX Parameterized Role for Resource Identifiers as per RFC3986 and RFC3987

# VERSION

# AUTHORITY

use Carp qw/croak/;
use Class::Method::Modifiers qw/install_modifier/;
use Encode qw//;
use Import::Into;
use Scalar::Does;
use Scalar::Util qw/blessed/;
use Marpa::R2;
use MarpaX::Role::Parameterized::ResourceIdentifier::Grammars;
use MarpaX::Role::Parameterized::ResourceIdentifier::MarpaTrace;
use MarpaX::Role::Parameterized::ResourceIdentifier::Setup;
use Module::Runtime qw/use_module/;
use Moo::Role;
use MooX::Role::Logger;
use MooX::Role::Parameterized;
use Role::Tiny;
use Types::Standard -all;
use Type::Params qw/compile/;

my $action_count = 0;
our $grammars    = MarpaX::Role::Parameterized::ResourceIdentifier::Grammars->instance;
our $setup       = MarpaX::Role::Parameterized::ResourceIdentifier::Setup->instance;

role {
  my $params = shift;

  #
  # Sanity check
  # ------------
  foreach (qw/BNF_package package encoding pct_encoded/) {
    croak "$_ must exist and do Str" unless exists($params->{$_}) && Str->check($params->{$_});
  }

  my $BNF_package       = $params->{BNF_package};
  my $package           = $params->{package};
  my $encoding          = $params->{encoding};
  my $pct_encoded       = $params->{pct_encoded};

  use_module($BNF_package);

  my $BNF_instance      = $BNF_package->new;
  my $start_symbol      = $BNF_instance->start_symbol;
  my $bnf               = $BNF_instance->bnf;

  croak "$BNF_package->bnf must do Str"                                       unless Str->check($bnf);
  croak "$BNF_package->bnf cannot have 'inaccessible is' (even if commented)" if $bnf =~ /\binaccessible\s+is\b/;
  croak "$BNF_package->bnf cannot have 'action =>' (even if commented)"       if $bnf =~ /\baction\s+=>/;

  $start_symbol      = "<$start_symbol>"      if substr($start_symbol,      0, 1) ne '<';
  my %start = (
               start_symbol      => $start_symbol,
              );

  my %G1 = ();
  if (exists($params->{G1})) {
    croak 'G1 reference type must be HASH' unless does $params->{G1}, 'HASH';
    foreach (keys %{$params->{G1}}) {
      # Every key must start with '<' and the value do CODE
      croak "G1 $_ must be in the form <...>" unless substr($_, 0, 1) eq '<';
      croak "G1 $_ value must do CODE" unless does $params->{G1}->{$_}, 'CODE';
      # It is illegal to have something for the percent encoded rule
      croak "G1 $_ key cannot be $start_symbol" if ($_ eq $pct_encoded);
    }
    %G1 = %{$params->{G1}};
  }
  #
  # Good, we can generate code and produce grammar singletons for start
  # -------------------------------------------------------------------
  #
  # In any case, we want Marpa to be "silent", unless explicitely traced
  #
  my $trace;
  open(my $trace_file_handle, ">", \$trace) || croak "Cannot open trace filehandle, $!";
  if ($setup->marpa_trace) {
    local $MarpaX::Role::Parameterized::ResourceIdentifier::MarpaTrace::BNF_PACKAGE = $BNF_package;
    tie ${$trace_file_handle}, 'MarpaX::Role::Parameterized::ResourceIdentifier::MarpaTrace';
  }
  foreach (qw/start/) {
    my $what = $_;
    my $start   = $start{"${what}_symbol"};
    my $action  = sprintf('__action%04d', ++$action_count);
    my $slif;
    if ($what eq 'start') {
      #
      # Main grammar: we just set the start symbol and the general action
      #
      $slif = <<SLIF;
inaccessible is ok by default
:start ::= $start
:default ::= action => ${package}::$action
$bnf
SLIF
    } else {
      #
      # Here we may modify SLIF for other start symbols.
      #
    }
    my $grammar = Marpa::R2::Scanless::G->new({source => \$slif, trace_file_handle => $trace_file_handle});
    #
    # Inject methods bnf and grammar methods per start symbol.
    # The deepest is the winner; i.e. specific, or generic, or common.
    #
    # install_modifier($package, $package->can("${what}_bnf")     ? 'around' : 'fresh', "${what}_bnf",     sub { $slif    } );
    # install_modifier($package, $package->can("${what}_grammar") ? 'around' : 'fresh', "${what}_grammar", sub { $grammar } );
    #
    # It is the deeper package that will win, but every layer (common, generic, specific) has its own grammar linked to a MooX::Struct.
    # And we will use this sub-grammar to fill such MooX::Struct. This is why we use a singleton to recover from
    # the different layers.
    #
    my $set_grammar_method_name = "set_${what}_grammar";
    $grammars->$set_grammar_method_name($package, $grammar);
    #
    # And it is exactly for the same reason that $action is unique per package
    # For performance reason, we have two versions w/o logging
    #
    my $action_sub;
    if ($setup->with_logger) {
      $action_sub = sub {
        my ($self, @args) = @_;
        my $slg         = $Marpa::R2::Context::slg;
        my ($lhs, @rhs) = map { $slg->symbol_display_form($_) } $slg->rule_expand($Marpa::R2::Context::rule);
        #
        # For simple symbols, symbol_display_form() removes the <>. Note that we enforced it upper, so we
        # are safe to enforce it here, eventually.
        #
        $lhs = "<$lhs>" if (substr($lhs, 0, 1) ne '<');
        #
        # We always propate only the concatenation
        #
        my $rc = ($lhs eq $pct_encoded) ? chr(hex("$args[1]$args[2]")) : join('', @args);
        $G1{$lhs}->($self, $rc) if exists $G1{$lhs};
        {
          local $\;
          $self->_logger->tracef('%s: %-30s ::= %s (%s --> %s)', $BNF_package, $lhs, \@rhs, \@args, $rc);
        }
        $rc;
      }
    } else {
      $action_sub = sub {
        my ($self, @args) = @_;
        my $slg         = $Marpa::R2::Context::slg;
        my ($lhs, @rhs) = map { $slg->symbol_display_form($_) } $slg->rule_expand($Marpa::R2::Context::rule);
        #
        # For simple symbols, symbol_display_form() removes the <>. Note that we enforced it upper, so we
        # are safe to enforce it here, eventually.
        #
        $lhs = "<$lhs>" if (substr($lhs, 0, 1) ne '<');
        #
        # We always propate only the concatenation
        #
        my $rc = ($lhs eq $pct_encoded) ? chr(hex("$args[1]$args[2]")) : join('', @args);
        $G1{$lhs}->($self, $rc) if exists $G1{$lhs};
        $rc;
      }
    }
    install_modifier($package, 'fresh', $action, $action_sub);
  }
};

#
# Class methods common to any Resource Identifier
#
sub percent_encode {
  my ($class, $string, $regexp) = @_;

  my $encoded = $string;
  $encoded =~ s!$regexp!
    {
     #
     # ${^MATCH} is a read-only variable
     # and Encode::encode is affecting $match -;
     #
     my $match = ${^MATCH};
     join('', map { '%' . uc(unpack('H2', $_)) } split(//, Encode::encode('UTF-8', $match, Encode::FB_CROAK)))
    }
    !egp;
  $encoded
}

our $UTF8_tail = qr/[\x{80}-\x{BF}]/;
our $UTF8_1    = qr/[\x{00}-\x{7F}]/;
our $UTF8_2    = qr/[\x{C2}-\x{DF}]$UTF8_tail/;
our $UTF8_3    = qr/(?:[\x{E0}][\x{A0}-\x{BF}]$UTF8_tail)|(?:[\x{E1}-\x{EC}]$UTF8_tail$UTF8_tail)|(?:[\x{ED}][\x{80}-\x{9F}]$UTF8_tail)|(?:[\x{EE}-\x{EF}]$UTF8_tail$UTF8_tail)/;
our $UTF8_4    = qr/(?:[\x{F0}][\x{90}-\x{BF}]$UTF8_tail$UTF8_tail)|(?:[\x{F1}-\x{F3}]$UTF8_tail$UTF8_tail$UTF8_tail)|(?:[\x{F4}][\x{80}-\x{8F}]$UTF8_tail$UTF8_tail)/;
our $UTF8_char = qr/$UTF8_4|$UTF8_3|$UTF8_2|$UTF8_1/;
sub percent_decode {
  my ($class, $string) = @_;
  #
  # This is the regexp version of RFC3629, that will leave
  # every non-decodable thingy as is
  #
  my $decoded = $string;
  $decoded =~ s!$UTF8_char!
    {
     my $match = ${^MATCH};
     decode('UTF-8', $match, Encode::FB_CROAK)
    }
    !egp;
  $decoded
}

1;

=head1 SEE ALSO

L<Uniform Resource Identifier (URI): Generic Syntax|http://tools.ietf.org/html/rfc3986>

L<Internationalized Resource Identifier (IRI): Generic Syntax|http://tools.ietf.org/html/rfc3987>

L<Formats for IPv6 Scope Zone Identifiers in Literal Address Formats|https://tools.ietf.org/html/draft-fenner-literal-zone-02>

=cut
