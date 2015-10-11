use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier;
use Carp qw/croak/;
use Import::Into;
use Scalar::Does;
use Marpa::R2;
use Moo::Role;
use MooX::Role::Parameterized;

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
  croak "BNF must exist and be a scalar"    unless exists($params->{BNF});
  croak "self_ref must exist and do SCALAR" unless exists($params->{self_ref});
  croak "start must exist and do SCALAR"    unless exists($params->{start});

  my $BNF      = $params->{BNF};
  my $self_ref = $params->{self_ref};
  my $start    = $params->{start};

  croak "BNF cannot have 'inaccessible is' (even if commented)" if ($BNF =~ /\binaccessible\s+is\b/);
  croak "BNF cannot have 'action =>' (even if commented)" if ($BNF =~ /\baction\s+=>/);

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
  $BNF = "inaccessible is ok by default\n:start ::= $start\n:default ::= action => " . __PACKAGE__ . "::__action\n$BNF";
  my $GRAMMAR = Marpa::R2::Scanless::G->new({source => \$BNF});
  method bnf     => sub { $BNF };
  method grammar => sub { $GRAMMAR };
  #
  # The generic action
  #
  method __action => sub {
    my (undef, @args) = @_;
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
    do { $G1{$lhs}->(${$self_ref}, @args) } if exists $G1{$lhs};
    #
    # What we propagage is ALWAYS the concatenation
    #
    join('', @args)
  }
};

1;

=head1 SEE ALSO

L<Uniform Resource Identifier (URI): Generic Syntax|http://tools.ietf.org/html/rfc3986>

L<Internationalized Resource Identifier (IRI): Generic Syntax|http://tools.ietf.org/html/rfc3987>

L<Formats for IPv6 Scope Zone Identifiers in Literal Address Formats|https://tools.ietf.org/html/draft-fenner-literal-zone-02>

=cut
