use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::_top;

# ABSTRACT: Internationalized Resource Identifier (IRI) : top implementation

# VERSION

# AUTHORITY

use MarpaX::Role::Parameterized::ResourceIdentifier::Types -all;
use Carp qw/croak/;
use Module::Runtime qw/use_module/;
use Moo::Role;
use Try::Tiny;
use Types::Standard -all;
use constant  { TRUE => !!1 };

my $_CALLER = undef;

sub import { $_CALLER = caller }

sub _new_from_specific {
  my ($class, $specific, $input) = @_;

  my $subclass = sprintf('%s::%s', $class, $specific);

  my $self;
  try {
    use_module($subclass);
    $self = $subclass->new($input);
    $self->_set_has_recognized_scheme(TRUE);
  };
  $self
}

sub _new_from_generic {
  my ($class, $input) = @_;

  my $subclass = sprintf('%s::%s', $class, '_generic');

  my $self;
  try {
    use_module($subclass);
    $self = $subclass->new($input);
  };
  $self
}

sub _new_from_common {
  my ($class, $input) = @_;

  my $subclass = sprintf('%s::%s', $class, '_common');
  use_module($subclass);

  $subclass->new($input)
}

sub new {
  my $class = shift;
  #
  # Input always exist, c.f. BUILDARGS
  #
  my $args = $class->BUILDARGS(@_);
  my $input = $args->{input};
  my $scheme = $args->{scheme};
  #
  # Specific: may fail, or even not exist
  #
  my $self;
  if ($input =~ /^[A-Za-z][A-Za-z0-9+.-]*(?=:)/p) {
    $self = $class->_new_from_specific(${^MATCH}, $input);
  }
  #
  # else _generic: may fail but try/catch'ed
  #
  $self = $class->_new_from_generic($input) if (! $self);
  #
  # fallback _common : must succeed
  #
  $self = $class->_new_from_common($input) if (! $self);
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
      $self = $class->_new_from_specific($real_scheme, $input) // $self;
    }
  }

  $self
}

with 'MarpaX::Role::Parameterized::ResourceIdentifier::Role::BUILDARGS';

1;
