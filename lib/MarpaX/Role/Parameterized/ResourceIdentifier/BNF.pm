use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::BNF;
use Moo::Role;

requires 'action_name';
requires 'grammar';
requires 'bnf';
requires 'reserved';
requires 'unreserved';
requires 'pct_encoded';
requires 'mapping';

1;
