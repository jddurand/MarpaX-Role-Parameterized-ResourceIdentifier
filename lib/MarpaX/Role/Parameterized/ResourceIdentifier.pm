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
  foreach (qw/start_symbol bnf pct_encoded utf8_octets reserved unreserved/) {
    $BNF{$_} = $BNF_instance->$_;
    if ($_ eq 'pct_encoded') {
      croak "$BNF_package->$_ must do Str or Undef" unless Str->check($BNF{$_}) || Undef->check($BNF{$_});
    } elsif ($_ eq 'utf8_octets') {
      croak "$BNF_package->$_ must do Bool or Undef" unless Bool->check($BNF{$_}) || Undef->check($BNF{$_});
    } elsif (($_ eq 'reserved') || ($_ eq 'unreserved')) {
      croak "$BNF_package->$_ must do RegexpRef or Undef" unless RegexpRef->check($BNF{$_}) || Undef->check($BNF{$_});
    } else {
      croak "$BNF_package->$_ must do Str" unless Str->check($BNF{$_});
    }
  }
  #
  # Extra protection: if reserved is a RegexpRef, then unreserved must be a RegexpRef
  #
  if (RegexpRef->check($BNF{reserved})) {
    croak "$BNF_package->unreserved must do RegexpRef" unless RegexpRef->check($BNF{unreserved});
  }

  croak "$BNF_package->bnf cannot have 'inaccessible is' (even if commented)" if $BNF{bnf} =~ /\binaccessible\s+is\b/;
  croak "$BNF_package->bnf cannot have 'action =>' (even if commented)"       if $BNF{bnf} =~ /\baction\s+=>/;

  foreach (qw/start_symbol pct_encoded/) {
    next if Undef->check($BNF{$_}); # Can happen only for pct_encoded
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
    croak 'G1 HASH must not contain an entry for $BNF{start_symbol}'          if $_ eq $BNF{start_symbol};
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
    # General stub to manage the reserved/unreserved indices
    #
    my $args2array_sub;
    if (Undef->check($BNF{reserved})) {
      #
      # No escape/unescape in output - at the most we decode the input
      #
      $args2array_sub = sub {
        my ($self, $lhs, $pct_encoded, $utf8_octets, @args) = @_;
        my $rc = ['', ''];
        foreach (@args) {
          #
          # When it is not an array ref, it is a lexeme
          #
          if (! ArrayRef->check($_)) {
            #
            # And there is a special lexeme: pct_encoded
            #
            if ($lhs eq $pct_encoded) {
              my $octets = '';
              while (m/(?<=%)[^%]+/gp) { $octets .= chr(hex(${^MATCH})) }
              $_ = $utf8_octets ? MarpaX::RFC::RFC3629->new($octets)->output : $octets
            }
            $rc->[0] .= $_, $rc->[1] .= $_
          } else {
            $rc->[0] .= $_->[0], $rc->[1] .= $_->[1]
          }
        }
        $rc
      }
    } else {
      my $reserved_regexp = $BNF{reserved};
      my $unreserved_regexp = $BNF{unreserved};
      #
      # We escape a character only if it is not in the reserved set, nor in the unreserved set,
      # i.e. we can use a single regexp: ! (reserved or unreserved)
      #
      my $character_not_to_escape = qr/(?:$reserved_regexp|$unreserved_regexp)/;
      $args2array_sub = sub {
        my ($self, $lhs, $pct_encoded, $utf8_octets, @args) = @_;
        my $rc = ['', ''];
        foreach (@args) {
          #
          # When it is not an array ref, it is a lexeme
          #
          if (! ArrayRef->check($_)) {
            #
            # And there is a special lexeme: pct_encoded
            #
            if ($lhs eq $pct_encoded) {
              my $octets = '';
              while (m/(?<=%)[^%]+/gp) { $octets .= chr(hex(${^MATCH})) }
              $_ = $utf8_octets ? MarpaX::RFC::RFC3629->new($octets)->output : $octets
            }
            #
            # Unescaped is per def the current input, eventually percent decoded
            #
            my ($escaped, $unescaped) = ('', $_);
            foreach (split(//, $_)) {
              $escaped .=
                ($_ =~ $character_not_to_escape) ?
                  $_
                  :
                  do {
                    #
                    # Because Encode::encode does not like read-only values
                    #
                    my $character = $_;
                    join('', map { '%' . uc(unpack('H2', $_)) } split(//, Encode::encode('UTF-8', $character, Encode::FB_CROAK)))
                  }
            }
            $rc->[0] .= $escaped, $rc->[1] .= $unescaped
          } else {
            $rc->[0] .= $_->[0], $rc->[1] .= $_->[1]
          }
        }
        $rc
      };
    }
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
        # We always propagate only an ArrayRef containing a concatenation, except then
        # $lhs is start_symbol, then we return $self.
        # The indice 0 of the array ref contains the unescaped string: this is just a
        # concatenation of what came in.
        # The indice 1 of the array ref contains the escaped string, and the rule is:
        # - If the indice 1 is not setted (predicate is false), then:
        #   - for every character not in the reserved set, escape any character not in the unreserved set
        # From implementation point of view:
        # - "reserved"   is always a regexp equivalent to the <reserved>   (unproductive) rule
        # - "unreserved" is always a regexp equivalent to the <unreserved> (  productive) rule
        #
        my $rc = &$args2array_sub($self, $lhs, $pct_encoded, $utf8_octets, @args);
        do { $G1{$lhs}->($self->[0], $rc->[0]), $G1{$lhs}->($self->[1], $rc->[1]) } if exists $G1{$lhs};
        {
          #
          # Any of the indices can be taken as a logger
          #
          local $\;
          $self->[0]->_logger->tracef('%s: %-30s ::= %s (%s --> %s)', $BNF_package, $lhs, \@rhs, \@args, $rc);
        }
        $lhs eq $BNF{start_symbol} ? $self : $rc
      }
    } else {
      #
      # Version without logging
      #
      $default_action_sub = sub {
        my ($self, @args) = @_;
        my $slg         = $Marpa::R2::Context::slg;
        my ($lhs, @rhs) = map { $slg->symbol_display_form($_) } $slg->rule_expand($Marpa::R2::Context::rule);
        $lhs = "<$lhs>" if (substr($lhs, 0, 1) ne '<');
        my $rc = &$args2array_sub($self, $lhs, $pct_encoded, $utf8_octets, @args);
        do { $G1{$lhs}->($self->[0], $rc->[0]), $G1{$lhs}->($self->[1], $rc->[1]) } if exists $G1{$lhs};
        $lhs eq $BNF{start_symbol} ? $self : $rc
      }
    }
    install_modifier($package, 'fresh', $default_action, $default_action_sub);

    my $reserved = $BNF{reserved};
    my $can = $package->can('escape');
    if (RegexpRef->check($reserved)) {
      if ($can) {
        install_modifier($package, 'around', 'escape', sub { $_[1]->percent_encode($_[2], $reserved) });
      } else {
        install_modifier($package, 'fresh', 'escape', sub { $_[0]->percent_encode($_[1], $reserved) });
      }
    } else {
      if ($can) {
        install_modifier($package, 'around', 'escape', sub { $_[2] } );
      } else {
        install_modifier($package, 'fresh', 'escape', sub { $_[1] } );
      }
    }
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
