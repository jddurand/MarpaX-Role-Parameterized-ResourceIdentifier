package MarpaX::Role::Parameterized::ResourceIdentifier::Singleton;
use Moo;
with 'MooX::Singleton';
use MooX::HandlesVia;
use Types::Standard -all;

has _compiled_grammar_per_package  => ( is => 'rw',
                                        isa => HashRef[InstanceOf['Marpa::R2::Scanless::G']],
                                        default => sub { {} },
                                        handles_via => 'Hash',
                                        handles => {
                                                    _set_compiled_grammar_per_package => 'set',
                                                    _get_compiled_grammar_per_package => 'get'
                                                   }
                                      );

1;
