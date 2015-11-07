use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Impl::_top;
use MarpaX::Role::Parameterized::ResourceIdentifier::Setup;

# ABSTRACT: Resource Identifier: top level implementation

# VERSION

# AUTHORITY

use Carp qw/croak/;
use Module::Find qw/findsubmod/;
use Module::Runtime qw/use_module is_module_name/;
use Scalar::Util qw/blessed/;
use Try::Tiny;

our $setup  = MarpaX::Role::Parameterized::ResourceIdentifier::Setup->new;

sub _new_from_specific {
  my ($class, $args, $scheme) = @_;

  my $plugins_dirname       = $setup->plugins_dirname;
  my $can_scheme_methodname = $setup->can_scheme_methodname;

  my $plugins_namespace     = sprintf('%s::%s', $class, $plugins_dirname);

  my $self;

  foreach (findsubmod($plugins_namespace)) {
    #
    # Look if there is a class saying it is dealing with this scheme.
    # We require there is a class method able to answer to this
    # question: $can_scheme_methodname()
    #
    my $subclass = sprintf('%s::%s', $plugins_namespace, $_);
    try {
      use_module($subclass);
      #
      # This will natively croak if the subclass does not provide
      # this as a class method
      #
      if ($subclass->$can_scheme_methodname($scheme)) {
        $self = $subclass->new($args);
        $self->has_recognized_scheme(!!1);
      }
    };
    last if blessed($self);
  }

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
    croak $_ unless $setup->uri_compat;
    return
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
  my ($class, $args) = (shift, shift);
  #
  # scheme argument ?
  #
  my $self;

  $self = $class->_new_from_specific($args, @_) if (@_);
  $self = $class->_new_from_generic ($args)     unless blessed($self);
  $self = $class->_new_from_common  ($args)     unless blessed($self);

  $self
}

sub new_abs {
  my ($class, $args, $abs) = @_;

  $class->new($args)->abs($abs)
}

1;
