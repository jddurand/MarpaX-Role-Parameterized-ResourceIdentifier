use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::_common;

# ABSTRACT: Resource Identifier: Common syntax semantics

# VERSION

# AUTHORITY

use Moo::Role;
use Unicode::Normalize qw/normalize/;
use Types::Standard -all;
#
# Arguments of every callback:
# my ($self, $field, $value, $lhs) = @_;
#
around build_case_normalizer => sub {
  my ($orig, $self) = (shift, shift);
  my $rc = $self->$orig(@_);
  #
  # --------------------------------------------
  # http://tools.ietf.org/html/rfc3987
  # --------------------------------------------
  #
  # 5.3.2.1.  Case Normalization
  #
  # For all IRIs, the hexadecimal digits within a percent-encoding
  # triplet (e.g., "%3a" versus "%3A") are case-insensitive and therefore
  # should be normalized to use uppercase letters for the digits A - F.
  #
  $rc->{$self->pct_encoded} = sub { uc $_[2] } if (! Undef->check($self->pct_encoded));
  $rc
};

around build_character_normalizer => sub {
  my ($orig, $self) = (shift, shift);
  my $rc = $self->$orig(@_);
  #
  # --------------------------------------------
  # http://tools.ietf.org/html/rfc3987
  # --------------------------------------------
  #
  # 5.3.2.2.  Character Normalization
  #
  # [The exceptions are] conversion
  # from a non-digital form, and conversion from a non-UCS-based
  # character encoding to a UCS-based character encoding. In these cases,
  # NFC or a normalizing transcoder using NFC MUST be used for
  # interoperability.
  #
  $rc->{''} = sub { normalize('C',  $_[2]) } if (! $self->is_character_normalized);
  $rc
};

with 'MarpaX::Role::Parameterized::ResourceIdentifier::Role::BUILDARGS';

1;
