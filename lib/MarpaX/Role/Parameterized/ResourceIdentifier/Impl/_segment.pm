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

has input       => ( is => 'ro', isa => Str, required => 1 );
has unescape    => ( is => 'ro', isa => CodeRef, required => 1 );
has unreserved  => ( is => 'ro', isa => RegexpRef, required => 1 );
has _path       => ( is => 'rw', isa => Str );
has _parameters => ( is => 'rw', isa => ArrayRef[Str]);
#
# This is a copy of URI::_segment logic
#
sub BUILD {
  my ($self) = @_;

  my @segment = split(';', $self->input, -1);
  $segment[0] = $self->unescape->($segment[0], $self->unreserved);
  $self->_path(shift @segment);
  $self->_parameters(\@segment);
}

1;
