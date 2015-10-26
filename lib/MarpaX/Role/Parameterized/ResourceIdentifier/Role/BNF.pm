use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::BNF;
use Moo::Role;

requires 'action_name';
requires 'grammar';
requires 'bnf';
requires 'reserved';
requires 'unreserved';
requires 'pct_encoded';
requires 'is_utf8';
requires 'mapping';

1;
