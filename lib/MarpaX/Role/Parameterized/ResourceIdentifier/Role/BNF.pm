use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::BNF;
use Moo::Role;

requires 'bnf';
requires 'start_symbol';
requires 'pct_encoded';
requires 'utf8_octets';
requires 'reserved';
requires 'unreserved';
requires 'normalizer';

1;
