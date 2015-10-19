use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::_common;

# ABSTRACT: Internationalized Resource Identifier (IRI): _common role

# VERSION

# AUTHORITY

use Carp qw/croak/;
use Class::Method::Modifiers qw/install_modifier/;
use Encode qw/decode encode encode_utf8/;
use Module::Runtime qw/use_module/;
use MarpaX::Role::Parameterized::ResourceIdentifier::Grammars;
use MarpaX::Role::Parameterized::ResourceIdentifier::Setup;
use Moo::Role;
use MooX::Role::Parameterized;
use Types::Standard -all;
use Types::Encodings qw/Bytes/;
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
has bytes                 => ( is => 'rwp', isa => Bytes, trigger => 1);
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
  foreach (qw/BNF_package package encoding/) {
    croak "$_ must exist and do Str" unless exists($params->{$_}) && Str->check($params->{$_});
  }

  my $package      = $params->{package};
  my $BNF_package  = $params->{BNF_package};
  my $encoding     = $params->{encoding};

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
                           grammar => $grammars->get_start_grammar($package)
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
      #
      # input is a Perl string (UTF8)
      #
      $r->read(\$input);
      croak 'Parse of the input is ambiguous' if $r->ambiguous;
      {
        local $\;
        $self->_logger->tracef('%s: Getting common parse tree value as bytes', $package);
      }
      foreach (Common->FIELDS) {
        my $string = $self->_struct_common->$_;
        $self->_struct_common->$_(encode_utf8($string));
      }
      $self->_set_bytes(encode_utf8(${$r->value($struct_common)}));
      {
        local $\;
        $self->_logger->debugf('%s: Parse common tree value is %s', $package, $struct_common->TO_HASH);
      }
    }
  } else {
    $_trigger_input_sub = sub {
      my ($self, $input) = @_;
      my $r = Marpa::R2::Scanless::R->new(\%recognizer_option);
      my $struct_common = $self->_struct_common(Common->new);
      #
      # input is a Perl string (UTF8)
      #
      $r->read(\$input);
      croak 'Parse of the input is ambiguous' if $r->ambiguous;
      foreach (Common->FIELDS) {
        my $string = $self->_struct_common->$_;
        $self->_struct_common->$_(encode_utf8($string));
      }
      $self->_set_bytes(encode_utf8(${$r->value($struct_common)}));
    }
  }
  method _trigger_input => $_trigger_input_sub;

  my $_trigger_bytes_sub;
  if ($setup->with_logger) {
    $_trigger_bytes_sub = sub {
      my ($self, $input) = @_;
      {
        local $\;
        $self->_logger->tracef('%s: Encoding common output to %s', $package, $encoding);
      }
      my $bytes = $self->bytes;
      $self->_set_output(encode($encoding, $bytes, Encode::FB_CROAK));
      foreach (Common->FIELDS) {
        my $bytes = $self->_struct_common->$_;
        $self->_struct_common->$_(encode($encoding, $bytes, Encode::FB_CROAK));
      }
    }
  } else {
    $_trigger_bytes_sub = sub {
      my ($self, $input) = @_;
      my $bytes = $self->bytes;
      $self->_set_output(encode($encoding, $bytes, Encode::FB_CROAK));
      foreach (Common->FIELDS) {
        my $bytes = $self->_struct_common->$_;
        $self->_struct_common->$_(encode($encoding, $bytes, Encode::FB_CROAK));
      }
    }
  }
  method _trigger_bytes => $_trigger_bytes_sub;

 foreach (Common->FIELDS) {
    my $meth = $_;
    my $can = $package->can($meth);
    my $code = sub {
      my ($self, @args) = @_;
      my $rc = $self->_struct_common->$meth;
      $self->_struct_common->$meth(@args);
      $rc
    };
    install_modifier($package, 'fresh', $meth, $code);
  }

  install_modifier($package, 'fresh', 'is_relative', sub { FALSE });
  install_modifier($package, 'fresh', 'is_absolute', sub { FALSE });

};

1;
