use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::ldap;

# ABSTRACT: Resource Identifier: ldap syntax semantics common overrides role

# VERSION

# AUTHORITY

use Moo::Role;
BEGIN {
  #
  # Just to make role is composed before the arounds
  #
  with 'MarpaX::Role::Parameterized::ResourceIdentifier::Role::ldap';
}

around build_default_port => sub { 389 };
around build_secure       => sub { !!1 };

around percent_decode => sub {
  my ($orig, $self, $string, $characters_to_decode, $ascii_fallback) = (@_);
  #
  # Implementations SHOULD accept as input strings that are not valid UTF-8 strings
  # We interpret that as asking for ASCII fallback for any invalid UTF-8 string
  #
  $ascii_fallback = 1;
  $self->$orig($string, $characters_to_decode, $ascii_fallback);
};

around build_percent_encoding_normalizer => sub {
  my ($orig, $self) = (shift, shift);
  my $rc = $self->$orig(@_);
  #
  # LDAP grammar original grammar is based on OCTETS STRINGS, i.e. assuming
  # that input is ALREADY percent-decoded. So we use the unescaped generic
  # parse result as input to LDAP BNF... available in the "parent" -;
  #
  $rc->{''} = sub {
    my ($self, $field, $value, $lhs) = @_;
    my $unescaped = $MarpaX::Role::Parameterized::ResourceIdentifier::BNF::parent_self->unescaped;
    $unescaped
  };
  $rc->{'UTF8 octets'} = sub { MarpaX::RFC::RFC3629->new($_[2])->output };
  $rc->{'UTFMB'}       = sub { MarpaX::RFC::RFC3629->new($_[2])->output };
  $rc
};

1;
