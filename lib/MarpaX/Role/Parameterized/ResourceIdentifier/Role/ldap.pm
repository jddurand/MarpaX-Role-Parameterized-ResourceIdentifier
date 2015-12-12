use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::ldap;

# ABSTRACT: Resource Identifier: ldap syntax semantics common overrides role

# VERSION

# AUTHORITY

use Moo::Role;

around default_port => sub { 389 };

1;
