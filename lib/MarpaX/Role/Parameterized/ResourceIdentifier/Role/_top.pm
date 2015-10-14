use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::_top;

# ABSTRACT: Internationalized Resource Identifier (IRI): _top role

# VERSION

# AUTHORITY

use Moo::Role;
use Types::Standard -all;

has input => ( is => 'rwp', isa => Str, required => 1, trigger => 1);

sub BUILDARGS {
  my ($self, @args) = @_;
  unshift(@args, 'input') if @args % 2;
  return { @args };
};

sub _trigger_input {
}

1;
