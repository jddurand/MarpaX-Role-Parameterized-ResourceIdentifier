use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::BNF;
use Moo::Role;

requires 'bnf';
requires 'start_symbol';

1;

