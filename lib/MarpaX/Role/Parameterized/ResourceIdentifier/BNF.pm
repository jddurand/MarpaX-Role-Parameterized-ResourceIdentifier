use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::BNF;
use Moo::Role;

requires 'bnf';
requires 'escape';
requires 'unescape';
requires 'grammar_option';
requires 'recognizer_option';

1;

