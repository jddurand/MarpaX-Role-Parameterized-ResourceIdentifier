use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::_top;

# ABSTRACT: Internationalized Resource Identifier (IRI) : top implementation

# VERSION

# AUTHORITY

use Carp qw/croak/;
use Encode qw/decode/;
use Module::Runtime qw/use_module/;
use Moo::Role;
use MooX::Role::Parameterized;
use Try::Tiny;
use Types::Standard -all;
use Types::Encodings qw/Bytes/;

my $URI_COMPAT = 1;

sub import {
  my $package = shift;
  if (grep {$_ eq 'URI_COMPAT'} @_) {
    #
    # If this evals to a hash, take the value
    #
    my %args;
    eval { %args = @_ };
    $URI_COMPAT = $args{URI_COMPAT} // 0;
  }
}

sub _BUILDARGS {
  my $class = shift;

  #
  # We support one or two arguments exactly
  #
  croak 'Exactly one or two arguments are required: Str|ArrayRef, Str?' if ($#_ != 0 && $#_ != 1);
  #
  # First argument must be Str or ArrayRef
  #
  my $first = shift @_;
  croak 'First argument must be a string or an array reference' if (! Str->check($first) && ! ArrayRef->check($first));
  #
  # If first is an array ref, it must have at least two arguments pushed into decode()
  # - First is Str (encoding)
  # - Second is Bytes (bytes)
  # - Eventual third is Int (decode option)
  #
  my $input;
  if (ArrayRef->check($first)) {
    my @decode = @{$first};
    croak 'Array reference in first parameter must contain at least two elements' if ($#decode < 1);
    my $encoding = shift @decode;
    croak 'Array reference in first parameter must have a string as first element' if (! Str->check($encoding));
    my $bytes = shift @decode;
    croak 'Array reference in first parameter must have bytes as second element' if (! Bytes->check($bytes));
    if (@decode) {
      croak 'Array reference in first parameter must have an int as third element' if (! Int->check($decode[0]));
    }
    $input = decode($encoding, $bytes, @decode);
  } else {
    $input = $first;
  }
  #
  # Copy from URI:
  # Get rid of potential wrapping
  #
  $input =~ s/^<(?:URL:)?(.*)>$/$1/;
  $input =~ s/^"(.*)"$/$1/;
  $input =~ s/^\s+//;
  $input =~ s/\s+$//;
  my $args = { input => $input };
  #
  # Second argument must be Str
  #
  my $scheme = undef;
  if (@_) {
    $scheme = shift @_;
    croak 'Second argument me be a string' if (! Str->check($scheme));
    $args->{scheme} = $scheme;
  }
  #
  # Return arguments in a hash ref a per the spec
  #
  $args
}

sub new {
  my $class = shift;
  #
  # Input always exist, c.f. BUILDARGS
  #
  my $args = $class->_BUILDARGS(@_);
  my $input = $args->{input};
  my $scheme = $args->{scheme};
  local $MarpaX::Role::Parameterized::ResourceIdentifier::URI_COMPAT = $URI_COMPAT;
  #
  # Specific: may fail, or even not exist
  #
  my $self;
  if ($input =~ /^[A-Za-z][A-Za-z0-9+.-]*(?=:)/p) {
    try {
      my $subclass = sprintf('%s::%s', $class, ${^MATCH});
      use_module($subclass);
      $self = $subclass->new($input);
      #
      # Only in this case, the scheme is recognized
      #
      $self->_set_has_recognized_scheme(!!1);
    } catch {
      warn $_;
      return;
    }
  }
  #
  # else _generic: may fail
  #
  if (! $self) {
    try {
      my $subclass = sprintf('%s::%s', $class, '_generic');
      use_module($subclass);
      $self = $subclass->new($input);
    } catch {
      warn $_;
      return;
    }
  }
  #
  # fallback _common : must succeed
  #
  if (! $self) {
    my $subclass = sprintf('%s::%s', $class, '_common');
    use_module($subclass);
    $self = $subclass->new($input);
  }
  #
  # scheme argument
  #
  if (Str->check($scheme)) {
    if (! $self->can('is_relative')) {
      warn 'scheme argument ignored: implementation cannot tell if input is relative';
    } else {
      if ($self->is_relative) {
      }
    }
  }

  $self
}

1;
