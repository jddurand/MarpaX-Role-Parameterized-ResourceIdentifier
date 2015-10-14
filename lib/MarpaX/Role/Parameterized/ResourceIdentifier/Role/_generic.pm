use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::_generic;

# ABSTRACT: Internationalized Resource Identifier (IRI): _generic role

# VERSION

# AUTHORITY

use Carp qw/croak/;
use Class::Method::Modifiers qw/install_modifier/;
use Module::Runtime qw/use_module/;
use Moo::Role;
use MooX::Role::Parameterized;
use Types::Standard -all;
use MooX::Struct -rw,
  Generic => [
              hier_part => [ isa => Str|Undef, default => sub { undef } ],
              query     => [ isa => Str|Undef, default => sub { undef } ],
              authority => [ isa => Str|Undef, default => sub { undef } ],
              userinfo  => [ isa => Str|Undef, default => sub { undef } ],
              host      => [ isa => Str|Undef, default => sub { undef } ],
              port      => [ isa => Str|Undef, default => sub { undef } ],
            ];

has _struct_generic => ( is => 'rw',  isa => Object);

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

  install_modifier($package, 'around', '_trigger_input',
                   sub {
                     my ($orig, $self, $input) = @_;
                     $self->$orig($input);
                     $self->_struct_generic(${$self->grammar->parse(
                                                                    \$input,
                                                                    {
                                                                     %{$BNF_package->recognizer_option},
                                                                     semantics_package => Generic
                                                                    }
                                                                   )
                                            }
                                           )
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
};

with 'MarpaX::Role::Parameterized::ResourceIdentifier::Role::_common';

requires 'hier_part';
requires 'query';
requires 'authority';

1;
