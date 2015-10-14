use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::_generic;

# ABSTRACT: Internationalized Resource Identifier (IRI): _generic role

# VERSION

# AUTHORITY

use Carp qw/croak/;
use Class::Method::Modifiers qw/install_modifier/;
use Module::Runtime qw/use_module/;
use MarpaX::Role::Parameterized::ResourceIdentifier::Singleton;
use Moo::Role;
use MooX::Role::Parameterized;
use Types::Standard -all;
use MooX::Role::Logger;
use MooX::Struct -rw,
  Generic => [
              hier_part => [ isa => Str|Undef, default => sub { undef } ],
              query     => [ isa => Str|Undef, default => sub { undef } ],
              authority => [ isa => Str|Undef, default => sub { undef } ],
              userinfo  => [ isa => Str|Undef, default => sub { undef } ],
              host      => [ isa => Str|Undef, default => sub { undef } ],
              port      => [ isa => Str|Undef, default => sub { undef } ],
            ];
use Role::Tiny;

has _struct_generic => ( is => 'rw',  isa => Object);

our $singleton = MarpaX::Role::Parameterized::ResourceIdentifier::Singleton->instance;

role {
  my $params = shift;

  croak "package     must exist and do Str" unless exists($params->{package}) && Str->check($params->{package});
  croak "BNF_package must exist and do Str" unless exists($params->{BNF_package}) && Str->check($params->{BNF_package});

  my $package      = $params->{package};
  my $BNF_package  = $params->{BNF_package};

  use_module($BNF_package);
  #
  # This is basically the inner of MooX::Role::Parameterized::With
  #
  use_module('MarpaX::Role::Parameterized::ResourceIdentifier')->apply($params, target => $package);
  Role::Tiny->apply_roles_to_package($package, qw/MooX::Role::Logger/);

  install_modifier($package, 'around', '_trigger_input',
                   sub {
                     my ($orig, $self, $input) = @_;
                     $self->_logger->debugf('%s: Instanciating recognizer', $package);
                     my $r = Marpa::R2::Scanless::R->new({
                                                          %{$BNF_package->recognizer_option},
                                                          grammar => $singleton->_get_compiled_grammar_per_package($package)
                                                         }
                                                        );
                     $r->read(\$input);
                     croak 'Parse of the input is ambiguous' if $r->ambiguous;
                     my $struct_generic = $self->_struct_generic(Generic->new);
                     Role::Tiny->apply_roles_to_object($struct_generic, qw/MooX::Role::Logger/);
                     $self->_logger->tracef('%s: Getting parse tree value', $package);
                     $r->value($struct_generic);
                     $self->_logger->tracef('%s: Parse tree value is %s', $package, $struct_generic->TO_HASH);
                     $self->_logger->tracef('%s: Back to orig call', $package);
                     $self->$orig($input);
                   }
                  );

  method hier_part => sub {
    my $self = shift;
    $self->_struct_generic->hier_part(@_);
  };

  method query => sub {
    my $self = shift;
    $self->_struct_generic->query(@_);
  };

  method authority => sub {
    my $self = shift;
    $self->_struct_generic->authority(@_);
  };

  method userinfo => sub {
    my $self = shift;
    $self->_struct_generic->host(@_);
  };

  method host => sub {
    my $self = shift;
    $self->_struct_generic->host(@_);
  };

  method port => sub {
    my $self = shift;
    $self->_struct_generic->port(@_);
  };
};

with 'MarpaX::Role::Parameterized::ResourceIdentifier::Role::_common';

#
# Make sure all fields of the structure are wrapped
#
foreach (Generic->FIELDS) {
  eval "requires '$_'";
}

1;
