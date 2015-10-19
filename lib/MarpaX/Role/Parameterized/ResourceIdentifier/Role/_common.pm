use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::_common;

# ABSTRACT: Internationalized Resource Identifier (IRI): _common role

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
has output                => ( is => 'rwp', isa => Str);
has has_recognized_scheme => ( is => 'rwp', isa => Bool, default => sub { FALSE } );
has _struct_common        => ( is => 'rw',  isa => Object);

our $grammars = MarpaX::Role::Parameterized::ResourceIdentifier::Grammars->instance;
our $setup    = MarpaX::Role::Parameterized::ResourceIdentifier::Setup->instance;

sub BUILDARGS {
  my ($class, @args) = @_;
  unshift @args, 'input' if @args % 2 == 1;
  return { @args }
}

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
  use_module('MarpaX::Role::Parameterized::ResourceIdentifier')->apply($params, target => $package);
  #
  # Logging
  #
  if ($setup->with_logger) {
    Role::Tiny->apply_roles_to_package($package, qw/MooX::Role::Logger/);
    install_modifier($package, $package->can('_build__logger_category') ? 'around' : 'fresh', '_build__logger_category', sub { $package });
    Role::Tiny->apply_roles_to_package(Common, qw/MooX::Role::Logger/);
    install_modifier(Common, Common->can('_build__logger_category') ? 'around' : 'fresh', '_build__logger_category', sub { $package });
  }
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
      my ($self, $input) = @_;
      {
        local $\;
        $self->_logger->tracef('%s: Instanciating common recognizer', $package);
      }
      my $r = Marpa::R2::Scanless::R->new(\%recognizer_option);
      my $struct_common = $self->_struct_common(Common->new);
      $r->read(\$input);
      croak 'Parse of the input is ambiguous' if $r->ambiguous;
      {
        local $\;
        $self->_logger->debugf('%s: Getting common parse tree value', $package);
      }
      $self->_set_output(${$r->value($struct_common)});
      {
        local $\;
        $self->_logger->debugf('%s: Common parse tree value is %s, structure is %s', $package, $self->output, $struct_common->TO_HASH);
      }
    }
  } else {
    $_trigger_input_sub = sub {
      my ($self, $input) = @_;
      my $r = Marpa::R2::Scanless::R->new(\%recognizer_option);
      my $struct_common = $self->_struct_common(Common->new);
      $r->read(\$input);
      croak 'Parse of the input is ambiguous' if $r->ambiguous;
      $self->_set_output(${$r->value($struct_common)});
    }
  }
  method _trigger_input => $_trigger_input_sub;

  foreach (Common->FIELDS) {
    my $meth = $_;
    my $can = $package->can($meth);
    my $code = sub {
      my $self = shift;
      my $rc = $self->_struct_common->$meth;
      $self->_struct_common->$meth(@_) if (@_);
      $rc
    };
    install_modifier($package, 'fresh', $meth, $code);
  }

  install_modifier($package, 'fresh', 'is_relative', sub { FALSE });
  install_modifier($package, 'fresh', 'is_absolute', sub { FALSE });

};

1;
