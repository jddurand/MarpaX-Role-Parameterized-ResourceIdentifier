use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::http;

# ABSTRACT: Resource Identifier: http syntax semantics common overrides role

# VERSION

# AUTHORITY

use Moo::Role;

around build_default_port => sub { 80 };
around normalized => sub {
  my ($orig, $self) = (shift, shift);
  my $normalized = $self->$orig(@_);

  if (defined($self->_authority) && (! length($self->_path)) && (! defined($self->_query))) {
    $self = $self->clone;
    $self->path("/");
    return $self->normalized  # No recurse because path is not empty
  } else {
    return $normalized
  }
};

1;
