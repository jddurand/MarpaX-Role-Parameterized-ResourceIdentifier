package MarpaX::Role::Parameterized::ResourceIdentifier::Singleton;
use Moo;
with 'MooX::Singleton';
use MooX::HandlesVia;
use Types::Standard -all;

has start_grammar  => ( is => 'rw',
                        isa => HashRef[InstanceOf['Marpa::R2::Scanless::G']],
                        default => sub { {} },
                        handles_via => 'Hash',
                        handles => {
                                    set_start_grammar => 'set',
                                    get_start_grammar => 'get'
                                   }
                      );

has gen_delims_grammar  => ( is => 'rw',
                             isa => HashRef[InstanceOf['Marpa::R2::Scanless::G']],
                             default => sub { {} },
                             handles_via => 'Hash',
                             handles => {
                                         set_gen_delims_grammar => 'set',
                                         get_gen_delims_grammar => 'get'
                                        }
                           );

1;
