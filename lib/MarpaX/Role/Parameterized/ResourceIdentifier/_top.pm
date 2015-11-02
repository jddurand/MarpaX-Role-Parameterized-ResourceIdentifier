use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::_top;

# ABSTRACT: Internationalized Resource Identifier (IRI) : _top role

# VERSION

# AUTHORITY

use MarpaX::Role::Parameterized::ResourceIdentifier::Setup;
use MarpaX::Role::Parameterized::ResourceIdentifier::Types -all;
use Carp qw/croak/;
use Log::Any qw/$log/;
use Module::Runtime qw/use_module/;
use Try::Tiny;
use Type::Params qw/compile/;
use Types::Standard -all;
use Types::TypeTiny qw/StringLike/;
use constant  { TRUE => !!1 };
#
# This is a not true role, though this package allow to inject what we want
#
use MooX::Role::Parameterized::With 'MarpaX::Role::Parameterized::ResourceIdentifier::BUILDARGS'
  => {
      whoami          => __PACKAGE__,
      type            => 'Top',
      second_argument => 'scheme',
     };

our $check_new_abs = compile(
                             StringLike,
                             ConsumerOf['MarpaX::Role::Parameterized::ResourceIdentifier'],
                             Maybe[Bool]
                            );
our $setup          = MarpaX::Role::Parameterized::ResourceIdentifier::Setup->instance;
my $_CALLER         = undef;

sub import { $_CALLER = caller }

sub _new_from_specific {
  my ($class, $specific, $args) = @_;

  my $subclass = sprintf('%s::%s', $class, $specific);

  my $self;
  try {
    my %args = %{$args};    # Always do a copy
    use_module($subclass);
    $self = $subclass->new(\%args);
    $self->_set_has_recognized_scheme(TRUE);
  } catch {
    foreach (split(/\n/, "$_")) {
      $log->tracef('%s: %s', $subclass, $_);
    }
    return;
  };
  $self
}

sub _new_from_generic {
  my ($class, $args) = @_;

  my $subclass = sprintf('%s::%s', $class, '_generic');

  my $self;
  try {
    my %args = %{$args};    # Always do a copy
    use_module($subclass);
    $self = $subclass->new(\%args);
  } catch {
    if ($setup->uri_compat) {
      foreach (split(/\n/, "$_")) {
        $log->tracef('%s: %s', $subclass, $_);
      }
    } else {
      croak $_;
    }
    return;
  };
  $self
}

sub _new_from_common {
  my ($class, $args) = @_;

  my $subclass = sprintf('%s::%s', $class, '_common');
  use_module($subclass);
  #
  # Should never fail
  #
  my %args = %{$args};    # Always do a copy
  $subclass->new(\%args)
}

sub new {
  my ($class) = shift;
  #
  # Input always exist, c.f. BUILDARGS
  #
  my $args = $class->BUILDARGS(@_);
  my $input = $args->{input};
  my $scheme = exists($args->{scheme}) ? $args->{scheme} : undef;
  #
  # Specific: may fail, or even not exist
  #
  my $self;
  if ($input =~ /^[A-Za-z][A-Za-z0-9+.-]*(?=:)/p) {
    $self = $class->_new_from_specific(${^MATCH}, $args);
  }
  #
  # else _generic: may fail but try/catch'ed
  #
  $self = $class->_new_from_generic($args) if (! $self);
  #
  # fallback _common : must succeed
  #
  $self = $class->_new_from_common($args) if (! $self);
  #
  # scheme argument
  #
  if (! Undef->check($scheme)) {
    #
    # Used only when input is relative
    #
    if ($self->is_relative) {
      #
      # Per def $scheme is passing SchemeLike|AbsoluteReference|StringifiedAbsoluteReference
      #
      my $real_scheme;
      if (SchemeLike->check($scheme)) {
        $real_scheme = $scheme;
      } elsif (AbsoluteReference->check($scheme)) {
        $real_scheme = $scheme->scheme;
      } elsif (StringifiedAbsoluteReference->check($scheme)) {
        $real_scheme = $_CALLER->new($scheme)->scheme;
      } else {
        croak 'Impossible case';
      }
      $self = $class->_new_from_specific($real_scheme, $args) // $self;
    }
  }

  $self
};

sub new_abs {
  my $class = shift;
  my ($ref, $base, $normalize) = $check_new_abs->($_[0], $_[1], $_[2]);
  #
  # 5.2.1.  Pre-parse the Base URI
  #
  # ./.. Note that only the scheme component is required to be
  # present in a base URI; the other components may be empty or
  # undefined.
  #
  croak 'base uri must have at least a scheme' unless Str->check($base->_scheme) && length($base->_scheme);
  #
  # ./.. Normalization of the base URI, as described in Sections 6.2.2 and 6.2.3, is optional
  #
  my $struct = $base->struct($normalize ? $base->indice_normalized : $base->indice_raw);

  # 5.2.2.  Transform References
  #
  # -- The URI reference is parsed into the five URI components
  # --
  #
  $ref = $class->new($ref);

  croak 'base uri must consume the generic syntax' unless (! grep { $struct->can($_) } qw/scheme authority path query fragment/);
  my $scheme    = $struct->scheme;
  my $authority = $struct->authority;
  my $path      = $struct->path;
  my $query     = $struct->query;
  my $fragment  = $struct->fragment;

}

1;
