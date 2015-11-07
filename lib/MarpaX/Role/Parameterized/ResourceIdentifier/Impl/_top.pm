use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Impl::_top;
use MarpaX::Role::Parameterized::ResourceIdentifier::Setup;

# ABSTRACT: Resource Identifier: top level implementation

# VERSION

# AUTHORITY

use Carp qw/croak/;
use Module::Runtime qw/use_module/;
use Types::Standard -all;
use Try::Tiny;

our $setup  = MarpaX::Role::Parameterized::ResourceIdentifier::Setup->new;

sub _new_from_specific {
  my ($class, $args, $scheme) = @_;

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
  my ($class, $args) = @_;

  my $subclass = sprintf('%s::%s', $class, '_generic');

  my $self;
  try {
    use_module($subclass);
    $self = $subclass->new($args);
  } catch {
    croak $_ unless $setup->uri_compat
  };
  $self
}

sub _new_from_common {
  my ($class, $args) = @_;

  my $subclass = sprintf('%s::%s', $class, '_common');
  use_module($subclass);

  $subclass->new($args)
}

sub new {
  my ($class, $args, $scheme) = @_;
  #
  # scheme argument ?
  #
  my $self;
  if (! Undef->check($scheme)) {
    croak 'Second argument must do Str' unless Str->check($scheme);
    $self = $class->_new_from_specific($args, $scheme);
  }
  $self //= $class->_new_from_generic($args);
  $self //= $class->_new_from_common($args);

  $self
}

1;
