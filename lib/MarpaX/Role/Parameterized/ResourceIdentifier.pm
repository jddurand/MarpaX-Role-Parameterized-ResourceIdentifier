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
use MarpaX::RFC::RFC3629;
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

  my %BNF = ();
  foreach (qw/start_symbol bnf pct_encoded utf8_octets/) {
    $BNF{$_} = $BNF_instance->$_;
    if ($_ eq 'pct_encoded') {
      croak "$BNF_package->$_ must do Str or Undef" unless Str->check($BNF{$_}) || Undef->check($BNF{$_});
    } elsif ($_ eq 'utf8_octets') {
      croak "$BNF_package->$_ must do Bool or Undef" unless Bool->check($BNF{$_}) || Undef->check($BNF{$_});
    } else {
      croak "$BNF_package->$_ must do Str" unless Str->check($BNF{$_});
    }
  }

  croak "$BNF_package->bnf cannot have 'inaccessible is' (even if commented)" if $BNF{bnf} =~ /\binaccessible\s+is\b/;
  croak "$BNF_package->bnf cannot have 'action =>' (even if commented)"       if $BNF{bnf} =~ /\baction\s+=>/;

  foreach (qw/start_symbol pct_encoded/) {
    next if Undef->check($BNF{$_});
    $BNF{$_} = '<' . $BNF{$_} . '>' if substr($BNF{$_}, 0, 1) ne '<';
  }

  croak 'G1 parameters must exist'                                            if (! exists $params->{G1});
  croak 'G1 reference type must be HASH'                                      unless does $params->{G1}, 'HASH';

  my %G1 = ();
  foreach (keys %{$params->{G1}}) {
    # Every key must start with '<' and the value do CODE
    croak "G1 $_ must be in the form <...>" unless substr($_, 0, 1) eq '<';
    croak "G1 $_ value must do CODE" unless does $params->{G1}->{$_}, 'CODE';
    $G1{$_} = $params->{G1}->{$_};
    croak 'G1 HASH must not contain an entry for $BNF{pct_encoded}'           if Str->check($BNF{pct_encoded}) && $_ eq $BNF{pct_encoded};
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
  {
    my $start_symbol       = $BNF{start_symbol};
    my $default_action     = sprintf('__action%04d', ++$action_count);
    my $slif           = <<SLIF;
inaccessible is ok by default
:start ::= $start_symbol
:default ::= action => ${package}::$default_action
$BNF{bnf}
SLIF
    #
    # Compile and save grammar.
    #
    # It is the deepest package that will win, but every layer (common, generic, specific) has its own grammar linked to a MooX::Struct.
    # And we will use this sub-grammar to fill such MooX::Struct. This is why we use a singleton to recover from
    # the different layers.
    #
    my $grammar = Marpa::R2::Scanless::G->new({source => \$slif, trace_file_handle => $trace_file_handle});
    $grammars->set_grammar($package, $grammar);
    #
    # Generate default action
    #
    my $default_action_sub;
    my $pct_encoded = Str->check($BNF{pct_encoded}) ? $BNF{pct_encoded} : '';
    my $utf8_octets = Bool->check($BNF{utf8_octets}) ? $BNF{utf8_octets} : 0;
    if ($setup->with_logger) {
      $default_action_sub = sub {
        my ($self, @args) = @_;
        my $slg         = $Marpa::R2::Context::slg;
        my ($lhs, @rhs) = map { $slg->symbol_display_form($_) } $slg->rule_expand($Marpa::R2::Context::rule);
        #
        # For simple symbols, symbol_display_form() removes the <>. Note that we enforced it upper, so we
        # are safe to enforce it here, eventually.
        #
        $lhs = "<$lhs>" if (substr($lhs, 0, 1) ne '<');
        #
        # We always propagate only the concatenation
        #
        my $rc = join('', @args);
        if ($lhs eq $pct_encoded) {
          my $octets = '';
          while ($rc =~ m/(?<=%)[^%]+/gp) { $octets .= chr(hex(${^MATCH})) }
          $rc = $utf8_octets ? MarpaX::RFC::RFC3629->new($octets)->output : $octets;
        }
        $G1{$lhs}->($self, $rc) if exists $G1{$lhs};
        {
          local $\;
          $self->_logger->tracef('%s: %-30s ::= %s (%s --> %s)', $BNF_package, $lhs, \@rhs, \@args, $rc);
        }
        $rc;
      }
    } else {
      #
      # The version without logging is splitted w/o pct_encoded for performance reasons
      #
      if (length($pct_encoded)) {
        if ($utf8_octets) {
          $default_action_sub = sub {
            my ($self, @args) = @_;
            my $slg         = $Marpa::R2::Context::slg;
            my ($lhs, @rhs) = map { $slg->symbol_display_form($_) } $slg->rule_expand($Marpa::R2::Context::rule);
            $lhs = "<$lhs>" if (substr($lhs, 0, 1) ne '<');
            my $rc = join('', @args);
            if ($lhs eq $pct_encoded) {
              my $octets = '';
              while ($rc =~ m/(?<=%)[^%]+/gp) { $octets .= chr(hex(${^MATCH})) }
              $rc = MarpaX::RFC::RFC3629->new($octets)->output;
            }
            $G1{$lhs}->($self, $rc) if exists $G1{$lhs};
            $rc
          }
        } else {
          $default_action_sub = sub {
            my ($self, @args) = @_;
            my $slg         = $Marpa::R2::Context::slg;
            my ($lhs, @rhs) = map { $slg->symbol_display_form($_) } $slg->rule_expand($Marpa::R2::Context::rule);
            $lhs = "<$lhs>" if (substr($lhs, 0, 1) ne '<');
            my $rc = join('', @args);
            if ($lhs eq $pct_encoded) {
              my $octets = '';
              while ($rc =~ m/(?<=%)[^%]+/gp) { $octets .= chr(hex(${^MATCH})) }
              $rc = $octets;
            }
            $G1{$lhs}->($self, $rc) if exists $G1{$lhs};
            $rc
          }
        }
      } else {
        $default_action_sub = sub {
          my ($self, @args) = @_;
          my $slg         = $Marpa::R2::Context::slg;
          my ($lhs, @rhs) = map { $slg->symbol_display_form($_) } $slg->rule_expand($Marpa::R2::Context::rule);
          $lhs = "<$lhs>" if (substr($lhs, 0, 1) ne '<');
          my $rc = join('', @args);
          $G1{$lhs}->($self, $rc) if exists $G1{$lhs};
          $rc
        }
      }
    }
    install_modifier($package, 'fresh', $default_action, $default_action_sub);
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

1;

=head1 SEE ALSO

L<Uniform Resource Identifier (URI): Generic Syntax|http://tools.ietf.org/html/rfc3986>

L<Internationalized Resource Identifier (IRI): Generic Syntax|http://tools.ietf.org/html/rfc3987>

L<Formats for IPv6 Scope Zone Identifiers in Literal Address Formats|https://tools.ietf.org/html/draft-fenner-literal-zone-02>

=cut
