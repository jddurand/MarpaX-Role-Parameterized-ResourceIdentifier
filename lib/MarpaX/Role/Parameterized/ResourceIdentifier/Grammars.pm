package MarpaX::Role::Parameterized::ResourceIdentifier::Grammars;
use Moo;
with 'MooX::Singleton';
use MooX::HandlesVia;
use Types::Standard -all;

has grammar  => ( is => 'rw',
                  isa => HashRef[InstanceOf['Marpa::R2::Scanless::G']],
                  default => sub { {} },
                  handles_via => 'Hash',
                  handles => {
                              set_grammar => 'set',
                              get_grammar => 'get'
                             }
                );
1;
