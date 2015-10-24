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
our $setup    = MarpaX::Role::Parameterized::ResourceIdentifier::Setup->instance;
use MooX::Struct
  Generic => [
              _output         => [ is => 'rw',  isa => Str,           default => sub {    '' } ], # Parse tree value
              iri             => [ is => 'rwp', isa => Str|Undef,     default => sub { undef } ],
              opaque          => [ is => 'rwp', isa => Str,           default => sub {    '' } ],
              scheme          => [ is => 'rwp', isa => Str|Undef,     default => sub { undef } ],
              hier_part       => [ is => 'rwp', isa => Str|Undef,     default => sub { undef } ],
              query           => [ is => 'rwp', isa => Str|Undef,     default => sub { undef } ],
              fragment        => [ is => 'rwp', isa => Str|Undef,     default => sub { undef } ],
              segment         => [ is => 'rwp', isa => Str|Undef,     default => sub { undef } ],
              authority       => [ is => 'rwp', isa => Str|Undef,     default => sub { undef } ],
              path            => [ is => 'rwp', isa => Str|Undef,     default => sub { undef } ],
              path_abempty    => [ is => 'rwp', isa => Str|Undef,     default => sub { undef } ],
              path_absolute   => [ is => 'rwp', isa => Str|Undef,     default => sub { undef } ],
              path_noscheme   => [ is => 'rwp', isa => Str|Undef,     default => sub { undef } ],
              path_rootless   => [ is => 'rwp', isa => Str|Undef,     default => sub { undef } ],
              path_empty      => [ is => 'rwp', isa => Str|Undef,     default => sub { undef } ],
              relative_ref    => [ is => 'rwp', isa => Str|Undef,     default => sub { undef } ],
              relative_part   => [ is => 'rwp', isa => Str|Undef,     default => sub { undef } ],
              userinfo        => [ is => 'rwp', isa => Str|Undef,     default => sub { undef } ],
              host            => [ is => 'rwp', isa => Str|Undef,     default => sub { undef } ],
              port            => [ is => 'rwp', isa => Str|Undef,     default => sub { undef } ],
              ip_literal      => [ is => 'rwp', isa => Str|Undef,     default => sub { undef } ],
              ipv4_address    => [ is => 'rwp', isa => Str|Undef,     default => sub { undef } ],
              reg_name        => [ is => 'rwp', isa => Str|Undef,     default => sub { undef } ],
              ipv6_address    => [ is => 'rwp', isa => Str|Undef,     default => sub { undef } ],
              ipv6_addrz      => [ is => 'rwp', isa => Str|Undef,     default => sub { undef } ],
              ipvfuture       => [ is => 'rwp', isa => Str|Undef,     default => sub { undef } ],
              zoneid          => [ is => 'rwp', isa => Str|Undef,     default => sub { undef } ],
              segments        => [ is => 'rwp', isa => ArrayRef[Str], default => sub { $setup->uri_compat ? [''] : [] } ],
             ];
use Role::Tiny;
use Scalar::Util qw/blessed/;

#
# Indice 0: escaped value, indice 1: unescaped value
#
has _structs => ( is => 'rw', isa => ArrayRef[Object]);              # Indice 0: escaped, Indice 1: unescaped

our $grammars = MarpaX::Role::Parameterized::ResourceIdentifier::Grammars->instance;

role {
  my $params = shift;

  requires 'idn'; # has idn      => ( is => 'rw', isa => Bool, default => sub { !!0 } ); # Is reg-name an IDN
  requires 'is_character_normalized';
  requires 'character_normalization_strategy';

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
        $self->_logger->tracef('%s: Instanciating generic recognizer', $package);
      }
      my $r = Marpa::R2::Scanless::R->new(\%recognizer_option);
      try {
        $r->read(\$input);
        croak 'Parse of the input is ambiguous' if $r->ambiguous;
        {
          local $\;
          $self->_logger->tracef('%s: Getting generic parse tree value', $package);
        }
        $self->_structs([map { Generic->new } (0..$self->_indice__max) ]);
        $r->value($self);
        foreach (0..$self->_indice__max) {
          local $\;
          $self->_logger->debugf('%s: %-30s = %s', $package, $self->_indice_description($_), $self->_structs->[$_]->_output);
        }
      } catch {
        if ($setup->uri_compat) {
          #
          # URI compatibility, it is supposed to match the generic syntax
          #
          $self->_logger->tracef('%s: Generic parsing failure', $package);
          foreach (split(/\n/, $_)) {
            $self->_logger->tracef('%s: %s', $package, $_);
          }
          #
          # This will do the parsing using the common BNF
          #
          $self->$orig($input);
        } else {
          #
          # Throw an error
          #
          croak $_;
        }
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
        $self->_structs([map { Generic->new } (0..$self->_indice__max) ]);
        $r->value($self);
      } catch {
        #
        # URI compatibility, it is supposed to match the generic syntax
        #
        $self->$orig($input);
        return
      };
    }
  }
  install_modifier($package, 'around', '_trigger_input', $_trigger_input_sub);
  #
  # Every internal field is accessible using _xxx, and eventually a boolean saying
  # if the output should be the escaped version, or the unescaped one.
  # Default indice is 0, i.e. it is returns the escaped string.
  #
  foreach (Generic->FIELDS) {
    my $field = $_;
    my $can = $package->can("_$field");
    my $code = sub { my $self = shift; $self->_structs->[$self->_indice(@_)]->$field };
    install_modifier($package,
                     $can ? 'around' : 'fresh',
                     "_$field",
                     $can ? sub { shift; goto &$code } : $code
                    );
  }

  my $normalize_sub = sub {
    my ($orig, $self, $field, $value) = @_;
    if ($field eq 'opaque') {
      print STDERR "TO OVERRIDE: $field normalization\n";
      $self->$orig($field, $value);
    } else {
      $self->$orig($field, $value);
    }
  };
  install_modifier($package, 'around', 'is_relative', sub { shift; Str->check(shift->_struct_generic->relative_ref) });
  install_modifier($package, 'around', 'is_absolute', sub { shift; Str->check(shift->_struct_generic->iri) });
};

1;
