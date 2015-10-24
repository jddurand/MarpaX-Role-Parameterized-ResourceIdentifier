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
use MarpaX::Role::Parameterized::ResourceIdentifier::Role::_top;
use Moo::Role;
use MooX::Role::Parameterized;
use Types::Standard -all;
#
# Base structure
#
use MooX::Struct
  Common => [
             _output  => [ is => 'rw',  isa => Str      , default => sub {    '' } ], # Parse tree value
             scheme   => [ is => 'rwp', isa => Str|Undef, default => sub { undef } ], # Can be undef
             opaque   => [ is => 'rwp', isa => Str      , default => sub {    '' } ], # Always set
             fragment => [ is => 'rwp', isa => Str|Undef, default => sub { undef } ]  # Can be undef
            ];

use Role::Tiny;
use Scalar::Util qw/blessed/;
use constant { FALSE => !!0 };

has input                 => ( is => 'ro',  isa => Str, required => 1, trigger => 1);
has has_recognized_scheme => ( is => 'rwp', isa => Bool, default => sub { FALSE } );
#
# Indice 0: escaped value, indice 1: unescaped value
#
has _structs              => ( is => 'rw',  isa => ArrayRef[Object]);

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
      $r->read(\$input);
      croak 'Parse of the input is ambiguous' if $r->ambiguous;
      {
        local $\;
        $self->_logger->tracef('%s: Getting common parse tree value', $package);
      }
      $self->_structs(${$r->value([
                                   Common->new,               # Raw
                                   Common->new,               # Escaped
                                   Common->new,               # Unescaped
                                   Common->new,               # Normalized raw
                                   Common->new,               # Normalized escaped
                                   Common->new                # Normalized unescaped
                                  ])});
      {
        local $\;
        $self->_logger->debugf('%s: Raw parse tree value                  is %s', $package, $self->_structs->[$self->_indice_raw                 ]->_output);
        $self->_logger->debugf('%s: Escaped parse tree value              is %s', $package, $self->_structs->[$self->_indice_escaped             ]->_output);
        $self->_logger->debugf('%s: Unescaped parse tree value            is %s', $package, $self->_structs->[$self->_indice_unescaped           ]->_output);
        $self->_logger->debugf('%s: Normalized raw parse tree value       is %s', $package, $self->_structs->[$self->_indice_normalized_raw      ]->_output);
        $self->_logger->debugf('%s: Normalized escaped parse tree value   is %s', $package, $self->_structs->[$self->_indice_normalized_escaped  ]->_output);
        $self->_logger->debugf('%s: Normalized unescaped parse tree value is %s', $package, $self->_structs->[$self->_indice_normalized_unescaped]->_output);
      }
    }
  } else {
    $_trigger_input_sub = sub {
      my ($self, $input) = @_;
      my $r = Marpa::R2::Scanless::R->new(\%recognizer_option);
      $r->read(\$input);
      croak 'Parse of the input is ambiguous' if $r->ambiguous;
      $self->_structs(${$r->value([
                                   Common->new,               # Raw
                                   Common->new,               # Escaped
                                   Common->new,               # Unescaped
                                   Common->new,               # Normalized raw
                                   Common->new,               # Normalized escaped
                                   Common->new                # Normalized unescaped
                                  ])});
    }
  }
  method _trigger_input => $_trigger_input_sub;

  my $top_package = $package;
  $top_package =~ s/::_common$//;

  method scheme => sub {
    my ($self, @args) = @_;
    #
    # Sets and returns the scheme part of the $uri.  If the $uri is relative, then $uri->scheme returns "undef".  If called with an argument, it updates the
    # scheme of $uri, possibly changing the class of $uri, and returns the old scheme value.  The method croaks if the new scheme name is illegal; a scheme
    # name must begin with a letter and must consist of only US-ASCII letters, numbers, and a few special marks: ".", "+", "-".  This restriction effectively
    # means that the scheme must be passed unescaped.  Passing an undefined argument to the scheme method makes the URI relative (if possible).
    #
    my $rc = $self->_scheme(undef, 1);  # Indice [0] and [1] will return the same thing as per scheme definition, second argument is normalization
    #
    # Letter case does not matter for scheme names.  The string returned by $uri->scheme is always lowercase.  If you want the scheme just as it was written in
    # the URI in its original case, you can use the $uri->_scheme method instead.};
    #
    $rc = lc($rc) if (Str->check($rc));
    #
    # Done like this, because the object can be reblessed
    #
    $_[0] = $top_package->new($self->_stringify(scheme => $args[0] // '')) if (@args);
    $rc
  };

  method _stringify => sub {
    my ($self, %args) = @_;

    my $uri = '';

    my $scheme   = delete($args{scheme});
    my $opaque   = delete($args{opaque});
    my $fragment = delete($args{fragment});

    my @internal_arguments = (delete($args{_unescape}), delete($args{_normalize}));

    $scheme   //= $self->_scheme(@internal_arguments)   // '';
    $opaque   //= $self->_opaque(@internal_arguments)   // '';
    $fragment //= $self->_fragment(@internal_arguments) // '';

    $uri .= $scheme . ':'   if (length($scheme));
    $uri .= $opaque         if (length($opaque));
    $uri .= '#' . $fragment if (length($fragment));

    $uri
  };
  #
  # Any kind of IRI comparison REQUIRES that all escapings or encodings
  # in the protocol or format ./.. are resolved. We have done it in the
  # unescaped indice.
  #
  method _eq_simple_string_comparison   => sub { $_[0]->_stringify(_unescape => 1)                  eq $_[1]->_stringify(_unescape => 1)                  };
  #
  # Syntax based normalization talks about <pct encoded> that should be
  # case insensitive.
  #
  # => We do not mind because we will use the unescaped version,
  # in which any <pct encoded> sequence has been converted to a character
  #
  # Next it says that IRIs MUST rely on the assumption that IRIs are
  # appropriately pre-character-normalized rather than apply character
  # normalization when comparing two IRIs.  The exceptions are conversion
  # from a non-digital form, and conversion from a non-UCS-based
  # character encoding to a UCS-based character encoding.
  #
  # => We simply do NOT support input that would come from a non-UCS-based character
  # encoding and indeed rely on the assumption stated above.
  #
  method _eq_syntax_based_normalization => sub { $_[0]->_stringify(_unescape => 1, _normalize => 1) eq $_[1]->_stringify(_unescape => 1, _normalize => 1) };
  method _eq                            => sub { _eq_simple_string_comparison(@_) || _eq_syntax_based_normalization(@_) };

  #
  # As per perldoc overload, Run-time overloading is only possible like this:
  #
  eval 'use overload (
                      \'""\' => sub { shift->_stringify },
                      \'==\' => sub {   _eq(@_) },
                      \'!=\' => sub { ! _eq(@_) }
                     )';
  method normalize => sub {
    my ($self, $field, $value) = @_;
    if ($field eq 'scheme') {
      $value = lc($value);
    }

    $value
  };
  #
  # Every internal field is accessible using _xxx, and eventually a boolean saying
  # if the output should be the escaped version, or the unescaped one.
  # Default indice is 0, i.e. it is returns the escaped string.
  #
  foreach (Common->FIELDS) {
    my $field = $_;
    method "_$field" => sub { my $self = shift; $self->_structs_generic->[$self->_indice(@_)]->$field };
  }
  method is_relative => sub { FALSE };
  method is_absolute => sub { FALSE };

  #
  # Help for indices
  #
  method _indice => sub {
    my ($self, $escaped, $unescaped, $raw) = @_;

    $escaped ? 0 : $unescaped ? 1 : 2
  };
};

1;
