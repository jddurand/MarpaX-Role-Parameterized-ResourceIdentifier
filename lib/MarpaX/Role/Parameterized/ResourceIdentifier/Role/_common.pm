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
use MooX::Struct -rw,
  Common => [
             scheme   => [ isa => Str|Undef, default => sub { undef } ], # Can be undef
             opaque   => [ isa => Str      , default => sub {    '' } ], # Always set
             fragment => [ isa => Str|Undef, default => sub { undef } ]  # Can be undef
            ];
use Role::Tiny;
use Scalar::Util qw/blessed/;
use constant { FALSE => !!0 };

has input                 => ( is => 'ro',  isa => Str, required => 1, trigger => 1);
has has_recognized_scheme => ( is => 'rwp', isa => Bool, default => sub { FALSE } );
has _struct_common        => ( is => 'rw',  isa => Object);

our $singleton = MarpaX::Role::Parameterized::ResourceIdentifier::Singleton->instance;
our $WITH_LOGGER = $ENV{'MarpaX::ResourceIdentifier::WITH_LOGGER'};

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
  if ($WITH_LOGGER) {
    Role::Tiny->apply_roles_to_package($package, qw/MooX::Role::Logger/);
    install_modifier($package, $package->can('_build__logger_category') ? 'around' : 'fresh', '_build__logger_category', sub { $package });
    Role::Tiny->apply_roles_to_package(Common, qw/MooX::Role::Logger/);
    install_modifier(Common, Common->can('_build__logger_category') ? 'around' : 'fresh', '_build__logger_category', sub { $package });
  }
  #
  # For performance reason, we have two versions w/o logging
  #
  my $_trigger_input_sub;
  if ($WITH_LOGGER) {
    $_trigger_input_sub = sub {
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
    }
  } else {
    $_trigger_input_sub = sub {
      my ($self, $input) = @_;
      my $r = Marpa::R2::Scanless::R->new({
                                           %{$BNF_package->recognizer_option},
                                           grammar => $singleton->_get_compiled_grammar_per_package($package)
                                          }
                                         );
      $r->read(\$input);
      croak 'Parse of the input is ambiguous' if $r->ambiguous;
      my $struct_common = $self->_struct_common(Common->new);
      $r->value($struct_common);
    }
  }
  method _trigger_input => $_trigger_input_sub;

  foreach (Common->FIELDS) {
    my $meth = $_;
    my $can = $package->can($meth);
    my $code = sub {
      my ($self, @args) = @_;
      my $rc = $self->_struct_generic->$meth;
      $self->_struct_generic->$meth(@_);
      $rc
    };
    install_modifier($package, 'fresh', $meth, $code);
  }

  install_modifier($package, 'fresh', 'is_relative', sub { FALSE });
  install_modifier($package, 'fresh', 'is_absolute', sub { FALSE });
};

requires 'has_recognized_scheme';
#
# Make sure all fields of the structure are wrapped
#
foreach (Common->FIELDS) {
  eval "requires '$_'";
}
#
# And add some methods that every object must do
#
requires 'is_relative';
requires 'is_absolute';

1;
