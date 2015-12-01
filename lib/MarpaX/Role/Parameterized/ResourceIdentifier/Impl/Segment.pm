use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Impl::Segment;

# ABSTRACT: Resource Identifier: segment implementation

# VERSION

# AUTHORITY

#
# For backward compatility with URI's path_segment
#
use overload '""' => sub { $_[0]->[0] }, fallback => 1;

#
# In contrary to original URI's _segment.pm:
# we create internal the object by sending all segments properly escaped/unescaped
#
sub new {
    my $class = shift;
    bless \@_, $class;
}

1;
