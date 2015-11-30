use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Impl::_segment;

# ABSTRACT: Resource Identifier: segment implementation

# VERSION

# AUTHORITY

#
# For backward compatility with URI, that makes a segment a separate
# object
#
use Moo;
use Types::Standard -all;
use overload '""' => sub { $_[0]->[0] }, fallback => 1;

has unescaped_proper_path => ( is => 'ro', isa => Str, required => 1 );
has escaped_parameters    => ( is => 'ro', isa => ArrayRef[Str], required => 1 );

1;
