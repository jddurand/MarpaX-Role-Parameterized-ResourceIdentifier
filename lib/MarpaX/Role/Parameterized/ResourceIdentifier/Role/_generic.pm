use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::_generic;

# ABSTRACT: Internationalized Resource Identifier (IRI): _generic role

# VERSION

# AUTHORITY

use Carp qw/croak/;
use Class::Method::Modifiers qw/install_modifier/;
use Module::Runtime qw/use_module/;
use MarpaX::Role::Parameterized::ResourceIdentifier::Grammars;
use MarpaX::Role::Parameterized::ResourceIdentifier::Setup;
use Moo::Role;
use MooX::Role::Parameterized;
use Types::Standard -all;
use Try::Tiny;
use MooX::Struct -rw,
  Generic => [
              iri             => [ isa => Str|Undef,     default => sub { undef } ],
              opaque          => [ isa => Str,           default => sub {    '' } ],
              scheme          => [ isa => Str|Undef,     default => sub { undef } ],
              hier_part       => [ isa => Str|Undef,     default => sub { undef } ],
              query           => [ isa => Str|Undef,     default => sub { undef } ],
              fragment        => [ isa => Str|Undef,     default => sub { undef } ],
              segment         => [ isa => Str|Undef,     default => sub { undef } ],
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
              ipv4_address    => [ isa => Str|Undef,     default => sub { undef } ],
              reg_name        => [ isa => Str|Undef,     default => sub { undef } ],
              ipv6_address    => [ isa => Str|Undef,     default => sub { undef } ],
              ipv6_addrz      => [ isa => Str|Undef,     default => sub { undef } ],
              ipvfuture       => [ isa => Str|Undef,     default => sub { undef } ],
              zoneid          => [ isa => Str|Undef,     default => sub { undef } ],
              segments        => [ isa => ArrayRef[Str], default => sub { [] } ],
              fragments       => [ isa => ArrayRef[Str], default => sub { [] } ],
             ];
use Role::Tiny;
use Scalar::Util qw/blessed/;

#
# Indice 0: escaped value, indice 1: unescaped value
#
has _structs_generic => ( is => 'rw', isa => ArrayRef[Object]);
has regnameconvert   => ( is => 'rw', isa => Bool, default => sub { 0 } );

our $grammars = MarpaX::Role::Parameterized::ResourceIdentifier::Grammars->instance;
our $setup    = MarpaX::Role::Parameterized::ResourceIdentifier::Setup->instance;

role {
  my $params = shift;

  #
  # Sanity check
  # ------------
  foreach (qw/BNF_package package/) {
    croak "$_ must exist and do Str" unless exists($params->{$_}) && Str->check($params->{$_});
  }

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
  if ($setup->with_logger) {
    Role::Tiny->apply_roles_to_package($package, qw/MooX::Role::Logger/);
    install_modifier($package, $package->can('_build__logger_category') ? 'around' : 'fresh', '_build__logger_category', sub { $package });
    Role::Tiny->apply_roles_to_package(Generic, qw/MooX::Role::Logger/);
    install_modifier(Generic, Generic->can('_build__logger_category') ? 'around' : 'fresh', '_build__logger_category', sub { $package });
  }
  #
  # "Parent" role
  #
  Role::Tiny->apply_roles_to_package($package, qw/MarpaX::Role::Parameterized::ResourceIdentifier::Role::_common/);
  #
  # Recognizer option is not configurable: we WILL modify the grammar and inject rules with a notion of rank
  #
  my %recognizer_option = (
                           trace_terminals =>  $setup->marpa_trace_terminals,
                           trace_values =>  $setup->marpa_trace_values,
                           ranking_method => 'high_rule_only',
                           grammar => $grammars->get_grammar($package)
                          );
  #
  # For performance reason, we have two versions w/o logging
  #
  my $_trigger_input_sub;
  if ($setup->with_logger) {
    $_trigger_input_sub = sub {
      my ($orig, $self, $input) = @_;
      {
        local $\;
        $self->_logger->debugf('%s: Instanciating generic recognizer', $package);
      }
      my $r = Marpa::R2::Scanless::R->new(\%recognizer_option);
      try {
        $r->read(\$input);
        croak 'Parse of the input is ambiguous' if $r->ambiguous;
        {
          local $\;
          $self->_logger->debugf('%s: Getting generic parse tree value', $package);
        }
        $self->_structs_generic(${$r->value([ Generic->new, Generic->new ])});
        {
          local $\;
          $self->_logger->debugf('%s: Escaped parse tree value is %s', $package, $self->_structs_generic->[0]->TO_HASH);
          $self->_logger->debugf('%s: Unescaped parse tree value is %s', $package, $self->_structs_generic->[1]->TO_HASH);
        }
      } catch {
        #
        # URI compatibility, it is supposed to match the generic syntax
        #
        $self->_logger->debugf('%s: Generic parsing failure', $package);
        foreach (split(/\n/, $_)) {
          $self->_logger->tracef('%s: %s', $package, $_);
        }
        #
        # This will do the parsing using the common BNF
        #
        $self->$orig($input);
        return
      };
    }
  } else {
    $_trigger_input_sub = sub {
      my ($orig, $self, $input) = @_;
      my $r = Marpa::R2::Scanless::R->new(\%recognizer_option);
      try {
        $r->read(\$input);
        croak 'Parse of the input is ambiguous' if $r->ambiguous;
        $self->_structs_generic(${$r->value([ Generic->new, Generic->new ])});
      } catch {
        $self->$orig($input);
      };
    }
  }
  install_modifier($package, 'around', '_trigger_input', $_trigger_input_sub);

  foreach (Generic->FIELDS) {
    my $meth = $_;
    my $can = $package->can($meth);
    my $code = sub {
      my $self = shift;
      my $rc = $self->_struct_generic->$meth;
      $self->_struct_generic->$meth(@_) if (@_);
      $rc
    };
    install_modifier($package,
                     $can ? 'around' : 'fresh',
                     $meth,
                     $can ? sub { shift; goto &$code } : $code
                    );
  }

  install_modifier($package, 'around', 'is_relative', sub { shift; Str->check(shift->_struct_generic->relative_ref) });
  install_modifier($package, 'around', 'is_absolute', sub { shift; Str->check(shift->_struct_generic->iri) });
};

1;
