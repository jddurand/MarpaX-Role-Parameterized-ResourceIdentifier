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
    print STDERR "BUILDARGS _generic\n";
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
                                            semantics_package => Generic
                                           }
                                          )
                   }
                  )
  };

  method hier_part => sub {
    my $self = shift;
    $self->_struct->hier_part(@_);
  };

  method query => sub {
    my $self = shift;
    $self->_struct->query(@_);
  };

  method authority => sub {
    my $self = shift;
    $self->_struct->authority(@_);
  };
};

with 'MarpaX::Role::Parameterized::ResourceIdentifier::Role::_common';

1;
