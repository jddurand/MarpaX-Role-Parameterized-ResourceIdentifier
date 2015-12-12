use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::ldap;

# ABSTRACT: Resource Identifier: ldap syntax semantics common overrides role

# VERSION

# AUTHORITY

use Moo::Role;

around default_port => sub { 389 };

around build_percent_encoding_normalizer => sub {
  my ($orig, $self) = (shift, shift);
  my $rc = $self->$orig(@_);
  #
  # --------------------------------------------
  # http://tools.ietf.org/html/rfc3987
  # --------------------------------------------
  #
  # 5.3.2.3.  Percent-Encoding Normalization
  #
  # ./.. IRIs should be normalized by decoding any
  # percent-encoded octet sequence that corresponds to an unreserved
  # character, as described in section 2.3 of [RFC3986].
  #
  if (defined($self->pct_encoded) && defined($self->unreserved)) {
    my $unreserved = $self->unreserved;
    $rc->{LDAPString} = sub { $_[0]->percent_decode($_[2], $unreserved) }
  }
  $rc
};

1;
