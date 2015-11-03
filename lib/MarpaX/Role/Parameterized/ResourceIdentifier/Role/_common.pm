use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::_common;

# ABSTRACT: Resource Identifier: _common role

# VERSION

# AUTHORITY

use Moo::Role;
use Types::Standard -all;
#
# common implementation has no normalizer
#
sub build_case_normalizer             { return {} }
sub build_character_normalizer        { return {} }
sub build_percent_encoding_normalizer { return {} }
sub build_path_segment_normalizer     { return {} }
sub build_scheme_based_normalizer     { return {} }
sub build_protocol_based_normalizer   { return {} }
sub build_uri_converter               { return {} }
sub build_iri_converter               { return {} }

1;
