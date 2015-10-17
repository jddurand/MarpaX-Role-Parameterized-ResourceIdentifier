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
  foreach (qw/BNF_package package/) {
    croak "$_ must exist and do Str" unless exists($params->{$_}) && Str->check($params->{$_});
  }

  my $BNF_package       = $params->{BNF_package};
  my $package           = $params->{package};

  use_module($BNF_package);

  my $BNF_instance      = $BNF_package->new;
  my $start_symbol      = $BNF_instance->start_symbol;
  my $gen_delims_symbol = $BNF_instance->gen_delims_symbol;
  my $bnf               = $BNF_instance->bnf;

  croak "$BNF_package->bnf must do Str"                                       unless Str->check($bnf);
  croak "$BNF_package->bnf cannot have 'inaccessible is' (even if commented)" if $bnf =~ /\binaccessible\s+is\b/;
  croak "$BNF_package->bnf cannot have 'action =>' (even if commented)"       if $bnf =~ /\baction\s+=>/;

  $start_symbol      = "<$start_symbol>"      if substr($start_symbol,      0, 1) ne '<';
  $gen_delims_symbol = "<$gen_delims_symbol>" if substr($gen_delims_symbol, 0, 1) ne '<';
  my %start = (
               start_symbol      => $start_symbol,
               gen_delims_symbol => $gen_delims_symbol
              );

  my %G1 = ();
  if (exists($params->{G1})) {
    croak 'G1 reference type must be HASH' unless does $params->{G1}, 'HASH';
    foreach (keys %{$params->{G1}}) {
      # Every key must start with '<' and the value do CODE
      croak "G1 $_ must be in the form <...>" unless substr($_, 0, 1) eq '<';
      croak "G1 $_ value must do CODE" unless does $params->{G1}->{$_}, 'CODE';
      # it is illegal to have a value for gen_delims: we will take it over
      croak "G1 $_ is not allowed" if ($_ eq $gen_delims_symbol);
    }
    %G1 = %{$params->{G1}};
    $G1{$gen_delims_symbol} = \&_percent_encode;
  }
  #
  # Good, we can generate code and produce grammar singletons for start and gen_delims
  # ----------------------------------------------------------------------------------
  #
  # In any case, we want Marpa to be "silent", unless explicitely traced
  #
  my $trace;
  open(my $trace_file_handle, ">", \$trace) || croak "Cannot open trace filehandle, $!";
  if ($setup->marpa_trace) {
    local $MarpaX::Role::Parameterized::ResourceIdentifier::MarpaTrace::BNF_PACKAGE = $BNF_package;
    tie ${$trace_file_handle}, 'MarpaX::Role::Parameterized::ResourceIdentifier::MarpaTrace';
  }
  foreach (qw/start gen_delims/) {
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
      # Delimiters grammar: we inject a rule in the grammar to catch everything, giving priority to gen_delims
      # that will have a specific action.
      # Anything not a delimiter will pass through.
      #
      $slif = <<SLIF;
inaccessible is ok by default
:start ::= <gen delims generated>
:default ::= action => ${package}::$action
$bnf

<gen delims generated>      ::= <gen delims generated unit>*

<gen delims generated unit> ::= $gen_delims_symbol             rank => 1
                             | <anything else generated>

<anything else generated>  ::= [\\s\\S]
SLIF
    }
    my $grammar = Marpa::R2::Scanless::G->new({source => \$slif, trace_file_handle => $trace_file_handle});
    #
    # Inject methods bnf and grammar methods per start symbol.
    # The deepest is the winner; i.e. specific, or generic, or common.
    #
    install_modifier($package, $package->can("${what}_bnf")     ? 'around' : 'fresh', "${what}_bnf",     sub { $slif    } );
    install_modifier($package, $package->can("${what}_grammar") ? 'around' : 'fresh', "${what}_grammar", sub { $grammar } );
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
        #
        # We always propate only the concatenation
        #
        my $rc = join('', @args);
        #
        # Specific sub-actions
        #
        my $slg         = $Marpa::R2::Context::slg;
        my ($lhs, @rhs) = map { $slg->symbol_display_form($_) } $slg->rule_expand($Marpa::R2::Context::rule);
        #
        # For simple symbols, symbol_display_form() removes the <>. Note that we enforced it upper, so we
        # are safe to enforce it here, eventually.
        #
        $lhs = "<$lhs>" if (substr($lhs, 0, 1) ne '<');
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
        #
        # We always propate only the concatenation
        #
        my $rc = join('', @args);
        #
        # Specific sub-actions
        #
        my $slg         = $Marpa::R2::Context::slg;
        my ($lhs, @rhs) = map { $slg->symbol_display_form($_) } $slg->rule_expand($Marpa::R2::Context::rule);
        #
        # For simple symbols, symbol_display_form() removes the <>. Note that we enforced it upper, so we
        # are safe to enforce it here, eventually.
        #
        $lhs = "<$lhs>" if (substr($lhs, 0, 1) ne '<');
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
  $encoded =~ s#($regexp)#
    {
     my $match = $1;
     join('', map { '%' . uc(unpack('H2', $_)) } split(//, Encode::encode('UTF-8', $match, Encode::FB_CROAK)))
    }
    #eg;
  $encoded
}

sub percent_decode {
  my ($class, $code) = @_;

  chr(hex($code))
}

1;

=head1 SEE ALSO

L<Uniform Resource Identifier (URI): Generic Syntax|http://tools.ietf.org/html/rfc3986>

L<Internationalized Resource Identifier (IRI): Generic Syntax|http://tools.ietf.org/html/rfc3987>

L<Formats for IPv6 Scope Zone Identifiers in Literal Address Formats|https://tools.ietf.org/html/draft-fenner-literal-zone-02>

=cut
