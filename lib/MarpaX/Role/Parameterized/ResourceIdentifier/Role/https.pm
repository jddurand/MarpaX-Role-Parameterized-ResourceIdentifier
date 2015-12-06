use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::https;

# ABSTRACT: Resource Identifier: https syntax semantics common overrides role

# VERSION

# AUTHORITY

use Moo::Role;
BEGIN {
  #
  # Just to make role is composed before the arounds
  #
  with 'MarpaX::Role::Parameterized::ResourceIdentifier::Role::http';
}

around build_default_port => sub { 443 };
around build_secure       => sub { !!1 };

1;
