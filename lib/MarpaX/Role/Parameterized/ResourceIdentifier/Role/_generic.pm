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
BEGIN { with 'MarpaX::Role::Parameterized::ResourceIdentifier::Role::_common' }
use MooX::Role::Logger;
use MooX::Role::Parameterized;
use Types::Standard -all;
use MooX::Struct -rw,
  Generic => [
              iri             => [ isa => Str|Undef,     default => sub { undef } ],
              scheme          => [ isa => Str|Undef,     default => sub { undef } ],
              hier_part       => [ isa => Str|Undef,     default => sub { undef } ],
              query           => [ isa => Str|Undef,     default => sub { undef } ],
              ifragment       => [ isa => Str|Undef,     default => sub { undef } ],
              isegment        => [ isa => Str|Undef,     default => sub { undef } ],
              authority       => [ isa => Str|Undef,     default => sub { undef } ],
              path            => [ isa => Str|Undef,     default => sub { undef } ],
              path_abempty    => [ isa => Str|Undef,     default => sub { undef } ],
              path_absolute   => [ isa => Str|Undef,     default => sub { undef } ],
              path_noscheme   => [ isa => Str|Undef,     default => sub { undef } ],
              path_rootless   => [ isa => Str|Undef,     default => sub { undef } ],
              path_empty      => [ isa => Str|Undef,     default => sub { undef } ],
              relative_ref    => [ isa => Str|Undef,     default => sub { undef } ],
              relative_part   => [ isa => Str|Undef,     default => sub { undef } ],
              userinfo        => [ isa => Str|Undef,     default => sub { undef } ],
              host            => [ isa => Str|Undef,     default => sub { undef } ],
              port            => [ isa => Str|Undef,     default => sub { undef } ],
              ip_literal      => [ isa => Str|Undef,     default => sub { undef } ],
              ipv6_address    => [ isa => Str|Undef,     default => sub { undef } ],
              ipv6_addrz      => [ isa => Str|Undef,     default => sub { undef } ],
              ipvfuture       => [ isa => Str|Undef,     default => sub { undef } ],
              zoneid          => [ isa => Str|Undef,     default => sub { undef } ],
              segments        => [ isa => ArrayRef[Str], default => sub { [] } ],
              fragments       => [ isa => ArrayRef[Str], default => sub { [] } ],
             ];
use Role::Tiny;
use Scalar::Util qw/blessed/;

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
  #
  # Logging
  #
  Role::Tiny->apply_roles_to_package($package, qw/MooX::Role::Logger/);
  install_modifier($package, $package->can('_build__logger_category') ? 'around' : 'fresh', '_build__logger_category', sub { $package });
  Role::Tiny->apply_roles_to_package(Generic, qw/MooX::Role::Logger/);
  install_modifier(Generic, Generic->can('_build__logger_category') ? 'around' : 'fresh', '_build__logger_category', sub { $package });

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
                     $self->_logger->tracef('%s: Getting parse tree value', $package);
                     $r->value($struct_generic);
                     $self->_logger->debugf('%s: Parse tree value is %s', $package, $struct_generic->TO_HASH);
                     $self->$orig($input);
                   }
                  );

  foreach (Generic->FIELDS) {
    #
    # We know in advance which methods already exist in the parent,
    # sure, but let's use this generic method generation
    #
    my $can = $package->can($_);
    install_modifier($package,
                     $can ? 'around' : 'fresh',
                     $_,
                     $can ? sub { shift; shift->_struct_generic->$_(@_) } : sub { shift->_struct_generic->$_(@_) }
                    );
  }
};

#
# Make sure all fields of the structure are wrapped
#
foreach (Generic->FIELDS) {
  eval "requires '$_'";
}

1;
