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

has _struct_common => ( is => 'rw',  isa => Object);

role {
  my $params = shift;

  croak "package     must exist and do Str" unless exists($params->{package}) && Str->check($params->{package});
  croak "BNF_package must exist and do Str" unless exists($params->{BNF_package}) && Str->check($params->{BNF_package});

  my $package      = $params->{package};
  my $BNF_package  = $params->{BNF_package};

  print STDERR "==> IN " . __PACKAGE__ . " APPLIED TO $package\n";

  use_module($BNF_package);
  use_module('MarpaX::Role::Parameterized::ResourceIdentifier')->apply($params, target => $package);

  install_modifier($package, 'around', '_trigger_input',
                   sub {
                     my ($orig, $self, $input) = @_;
                     $self->$orig($input);
                     $self->_struct_common(${$self->grammar->parse(
                                                                   \$input,
                                                                   {
                                                                    %{$BNF_package->recognizer_option},
                                                                    semantics_package => Common
                                                                   }
                                                                  )
                                           }
                                          )
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

requires 'has_recognized_scheme';
requires 'scheme';
requires 'opaque';
requires 'fragment';

1;
