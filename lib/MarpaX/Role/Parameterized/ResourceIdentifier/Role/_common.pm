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
use Scalar::Util qw/blessed/;

has input => ( is => 'ro', isa => Str, required => 1, trigger => 1);
has _struct_common => ( is => 'rw',  isa => Object);

our $singleton = MarpaX::Role::Parameterized::ResourceIdentifier::Singleton->instance;

sub BUILDARGS {
  my ($class, @args) = @_;
  unshift @args, 'input' if @args % 2 == 1;
  return { @args }
}

role {
  my $params = shift;

  croak "package     must exist and do Str" unless exists($params->{package}) && Str->check($params->{package});
  croak "BNF_package must exist and do Str" unless exists($params->{BNF_package}) && Str->check($params->{BNF_package});

  my $package      = $params->{package};
  my $BNF_package  = $params->{BNF_package};

  use_module($BNF_package);
  use_module('MarpaX::Role::Parameterized::ResourceIdentifier')->apply($params, target => $package);
  #
  # Logging
  #
  Role::Tiny->apply_roles_to_package($package, qw/MooX::Role::Logger/);
  install_modifier($package, 'around', '_build__logger_category', sub { __PACKAGE__ });
  Role::Tiny->apply_roles_to_package(Common, qw/MooX::Role::Logger/);
  install_modifier(Common, 'around', '_build__logger_category', sub { $package });

  method _trigger_input => sub {
    my ($self, $input) = @_;
    $self->_logger->tracef('%s: Instanciating recognizer', $package);
    my $r = Marpa::R2::Scanless::R->new({
                                         %{$BNF_package->recognizer_option},
                                         grammar => $singleton->_get_compiled_grammar_per_package($package)
                                        }
                                       );
    $r->read(\$input);
    croak 'Parse of the input is ambiguous' if $r->ambiguous;
    my $struct_common = $self->_struct_common(Common->new);
    $self->_logger->tracef('%s: Getting parse tree value', $package);
    $r->value($struct_common);
    $self->_logger->debugf('%s: Parse tree value is %s', $package, $struct_common->TO_HASH);
  };

  method has_recognized_scheme => sub { Str->check($_[0]->_struct_common->scheme) };

  foreach (Common->FIELDS) {
    my $meth = $_;
    my $can = $package->can($meth);
    install_modifier($package, 'fresh', $meth, sub { shift->_struct_common->$meth(@_) });
  }
};

requires 'has_recognized_scheme';
#
# Make sure all fields of the structure are wrapped
#
foreach (Common->FIELDS) {
  eval "requires '$_'";
}

1;
