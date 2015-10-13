use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::_common;

# ABSTRACT: Internationalized Resource Identifier (IRI): _common role

# VERSION

# AUTHORITY

use Carp qw/croak/;
use Class::Method::Modifiers qw/install_modifier/;
use Module::Runtime qw/use_module/;
use Moo::Role;
use MooX::Role::Parameterized;
use Types::Standard -all;
use MooX::Struct -rw,
  Common => [
             scheme   => [ isa => Str|Undef, default => sub { undef } ], # Can be undef
             opaque   => [ isa => Str      , default => sub {    '' } ], # Always set
             fragment => [ isa => Str|Undef, default => sub { undef } ]  # Can be undef
            ];

has input   => ( is => 'rwp', isa => Str,    required => 1, trigger => 1);
has _struct => ( is => 'rw',  isa => Object);

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

  method BUILDARGS => sub {
    print STDERR "BUILDARGS $package\n";
    print STDERR "=================\n";
    use Devel::StackTrace;
    my $trace = Devel::StackTrace->new();
    print STDERR $trace->as_string;

    my ($self, @args) = @_;
    unshift(@args, 'input') if @args % 2;
    return { @args };
  };

  method _trigger_input => sub {
    my ($self, $input) = @_;
    # $self->grammar->parse returns a reference to a value
    $self->_struct(${$self->grammar->parse(
                                           \$input,
                                           {
                                            %{$BNF_package->recognizer_option},
                                            semantics_package => Common
                                           }
                                          )
                   }
                  )
  };

  method has_recognized_scheme => sub {
    my ($self) = @_;
    Str->check($self->_struct->scheme)
  };

  method scheme => sub {
    my $self = shift;
    $self->_struct->scheme(@_);
  };

  method opaque => sub {
    my $self = shift;
    $self->_struct->opaque(@_);
  };

  method fragment => sub {
    my $self = shift;
    $self->_struct->fragment(@_);
  };
};

1;
