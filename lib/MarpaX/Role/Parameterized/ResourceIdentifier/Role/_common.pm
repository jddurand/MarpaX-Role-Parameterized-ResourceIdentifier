use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::_common;

# ABSTRACT: Internationalized Resource Identifier (IRI): _common role

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
  Common => [
             scheme   => [ isa => Str|Undef, default => sub { undef } ], # Can be undef
             opaque   => [ isa => Str      , default => sub {    '' } ], # Always set
             fragment => [ isa => Str|Undef, default => sub { undef } ]  # Can be undef
            ];
use Role::Tiny;

has _struct_common => ( is => 'rw',  isa => Object);

our $singleton = MarpaX::Role::Parameterized::ResourceIdentifier::Singleton->instance;

role {
  my $params = shift;

  croak "package     must exist and do Str" unless exists($params->{package}) && Str->check($params->{package});
  croak "BNF_package must exist and do Str" unless exists($params->{BNF_package}) && Str->check($params->{BNF_package});

  my $package      = $params->{package};
  my $BNF_package  = $params->{BNF_package};

  use_module($BNF_package);
  use_module('MarpaX::Role::Parameterized::ResourceIdentifier')->apply($params, target => $package);
  Role::Tiny->apply_roles_to_package($package, qw/MooX::Role::Logger/);

  install_modifier($package, 'around', '_trigger_input',
                   sub {
                     my ($orig, $self, $input) = @_;
                     $self->_logger->tracef('%s: Instanciating recognizer', $package);
                     my $r = Marpa::R2::Scanless::R->new({
                                                          %{$BNF_package->recognizer_option},
                                                          grammar => $singleton->_get_compiled_grammar_per_package($package)
                                                         }
                                                        );
                     $r->read(\$input);
                     croak 'Parse of the input is ambiguous' if $r->ambiguous;
                     my $struct_common = $self->_struct_common(Common->new);
                     Role::Tiny->apply_roles_to_object($struct_common, qw/MooX::Role::Logger/);
                     $self->_logger->tracef('%s: Getting parse tree value', $package);
                     $r->value($struct_common);
                     $self->_logger->tracef('%s: Parse tree value is %s', $package, $struct_common->TO_HASH);
                     $self->_logger->tracef('%s: Back to orig call', $package);
                     $self->$orig($input);
                   }
                  );

  method has_recognized_scheme => sub {
    my ($self) = @_;
    Str->check($self->_struct_common->scheme)
  };

  method scheme => sub {
    my $self = shift;
    $self->_struct_common->scheme(@_);
  };

  method opaque => sub {
    my $self = shift;
    $self->_struct_common->opaque(@_);
  };

  method fragment => sub {
    my $self = shift;
    $self->_struct_common->fragment(@_);
  };
};

with 'MarpaX::Role::Parameterized::ResourceIdentifier::Role::_top';

#
# Make sure all fields of the structure are wrapped
#
foreach (Common->FIELDS) {
  eval "requires '$_'";
}
requires 'has_recognized_scheme';

1;
