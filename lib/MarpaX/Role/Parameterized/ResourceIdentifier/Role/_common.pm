use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::_common;

# ABSTRACT: Resource Identifier: _common role

# VERSION

# AUTHORITY

use MarpaX::RFC::RFC3987::_top;
use Moo::Role;
use Types::Standard -all;

#
# All the hardwork is already done by the very top-level package, which is not
# a Moo package. I do not use FOREIGNARGS because it is not a parent.
#
sub BUILDARGS {
  my $class = shift;
  MarpaX::RFC::RFC3987::_top->BUILDARGS(@_)
}

#
# Common implementation has no normalizer except for scheme
#
# Arguments of every callback:
# my ($self, $field, $value, $lhs) = @_;
#
sub build_case_normalizer {
  my ($self) = @_;
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
  if (defined($self->pct_encoded)) {
    return { $self->pct_encoded => sub { uc $_[2] } }
  } else {
    return {}
  }
}
sub build_character_normalizer        { return {} }
sub build_percent_encoding_normalizer { return {} }
sub build_path_segment_normalizer     { return {} }
sub build_scheme_based_normalizer     { return {} }
sub build_protocol_based_normalizer   { return {} }
sub build_uri_converter               { return {} }
sub build_iri_converter               { return {} }

1;
