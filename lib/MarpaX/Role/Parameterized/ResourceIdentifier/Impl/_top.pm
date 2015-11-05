use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Impl::_top;

# ABSTRACT: Resource Identifier: top level implementation

# VERSION

# AUTHORITY

use Carp qw/croak/;
use MarpaX::Role::Parameterized::ResourceIdentifier::Role::BUILDARGS qw/BUILDARGS/;
use MarpaX::Role::Parameterized::ResourceIdentifier::Types -all;
use Module::Runtime qw/use_module/;
use Types::Standard -all;
use Try::Tiny;
use constant  { TRUE => !!1 };

my $_CALLER = undef;

sub import { $_CALLER = caller }

sub _new_from_specific {
  my ($class, $scheme, $args) = @_;

  $scheme = lc($scheme) unless exists($args->{is_scheme_case_sensitive}) && $args->{is_scheme_case_sensitive};
  my $subclass = sprintf('%s::%s', $class, $scheme);

  my %args = %{$args};
  $args{has_recognized_scheme} = 1;

  my $self;
  try {
    use_module($subclass);
    $self = $subclass->new(\%args);
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
  # Specific: may fail, or even not exist, else
  # _generic: may fail but try/catch'ed, else
  # _common : must succeed
  #
  my $self;
  if ($input =~ /^[A-Za-z][A-Za-z0-9+.-]*(?=:)/p) {
    $self = $class->_new_from_specific(${^MATCH}, $args);
  }
  $self = $class->_new_from_generic($args) if (! $self);
  $self = $class->_new_from_common($args)  if (! $self);
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
}

1;
