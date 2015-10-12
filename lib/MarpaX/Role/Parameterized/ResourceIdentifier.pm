use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier;
use Carp qw/croak/;
use Import::Into;
use Scalar::Does;
use Scalar::Util qw/blessed/;
use Marpa::R2;
use Moo::Role;
use MooX::Role::Parameterized;
use Types::Standard -all;
use Type::Params qw/compile/;

# ABSTRACT: MarpaX Parameterized Role for Resource Identifiers as per RFC3986 and RFC3987

# VERSION

# AUTHORTIY

# AUTHORITY

#
# URI/IRI are sharing EXACTLY the same implementation algorithm, only some names are changing.
#
# This is why they consume this parameterized role.
#
role {
  my $params = shift;

  #
  # Sanity check
  # ------------
  CORE::state $check_BNF = compile(ConsumerOf['MarpaX::Role::Parameterized::ResourceIdentifier::BNF']);

  croak "BNF must consume the role MarpaX::Role::Parameterized::ResourceIdentifier" unless exists($params->{BNF}) && $check_BNF->($params->{BNF});
  croak "start must exist do Str"                                                   unless exists($params->{start}) && Str->check($params->{start});

  my $bnf      = $params->{BNF}->bnf;
  my $start    = $params->{start};

  croak "BNF cannot have 'inaccessible is' (even if commented)" if ($bnf =~ /\binaccessible\s+is\b/);
  croak "BNF cannot have 'action =>' (even if commented)" if ($bnf =~ /\baction\s+=>/);

  my %G1 = ();
  if (exists($params->{G1})) {
    croak 'G1 reference type must be HASH' unless does $params->{G1}, 'HASH';
    foreach (keys %{$params->{G1}}) {
      # Every key must start with '<'
      croak "G1 $_ must be in the form <...>" unless substr($_, 0, 1) eq '<';
      # Every value must do CODE
      croak "G1 $_ value must do CODE" unless does $params->{G1}->{$_}, 'CODE';
    }
    %G1 = %{$params->{G1}};
  }
  #
  # Good, we can generate code and produce grammar singletons
  # ---------------------------------------------------------
  #
  # The BNF and the grammar that will look like a singleton
  #
  $bnf = "inaccessible is ok by default\n:start ::= $start\n:default ::= action => " . __PACKAGE__ . "::__action\n$bnf";
  my $GRAMMAR = Marpa::R2::Scanless::G->new({%{$params->{BNF}->grammar_option}, source => \$bnf});
  {
    no warnings 'redefine';
    #
    # Inject bnf and grammar methods
    #
    method bnf            => sub { $bnf };
    method grammar        => sub { $GRAMMAR };
    #
    # Inject escape/unescape internal methods
    #
    my $escape   = $params->{BNF}->escape;
    my $unescape = $params->{BNF}->unescape;
    method _escape   => sub { goto &$escape   };
    method _unescape => sub { goto &$unescape };
    #
    # Inject __parse method
    #
    method __parse => sub {
      my ($self, $input) = @_;
      $self->grammar->parse(\$input, $params->{BNF}->recognizer_option);
    };
    #
    # Inject grammar generic action
    #
    method __action => sub {
      my ($self, @args) = @_;
      #
      # We always propate only the concatenation, even if the scheme-specific rules
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
      exists $G1{$lhs} ? do { $G1{$lhs}->($self, $rc) } : $rc;
    }
  }
};

1;

=head1 SEE ALSO

L<Uniform Resource Identifier (URI): Generic Syntax|http://tools.ietf.org/html/rfc3986>

L<Internationalized Resource Identifier (IRI): Generic Syntax|http://tools.ietf.org/html/rfc3987>

L<Formats for IPv6 Scope Zone Identifiers in Literal Address Formats|https://tools.ietf.org/html/draft-fenner-literal-zone-02>

=cut
