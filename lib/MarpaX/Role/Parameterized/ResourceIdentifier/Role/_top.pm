use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::_top;

# ABSTRACT: Internationalized Resource Identifier (IRI) : top implementation

# VERSION

# AUTHORITY

use Encode qw/decode/;
use Module::Runtime qw/use_module/;
use Moo::Role;
use MooX::Role::Parameterized;
use Try::Tiny;
use Type::Params qw/compile/;
use Types::Standard -all;
use Types::TypeTiny qw/StringLike/;
use Types::Encodings qw/Bytes/;

my $URI_COMPAT = 1;
my $_CALLER = undef;

sub import {
  my $package = shift;
  $_CALLER = caller;

  if (grep {$_ eq 'URI_COMPAT'} @_) {
    #
    # If this evals to a hash, take the value
    #
    my %args;
    eval { %args = @_ };
    $URI_COMPAT = $args{URI_COMPAT} // 0;
  }
}

our $schemelike = "Type::Tiny"->new(
                                    name       => "SchemeLike",
                                    constraint => sub { $_ =~ /^[A-Za-z][A-Za-z0-9+.-]*$/ },
                                    message    => sub { "$_ ain't looking like a scheme" },
                                   );

our $absolute_reference = "Type::Tiny"->new(
                                            name       => "AbsoluteResourceIdentifier",
                                            constraint => sub { ConsumerOf[__PACKAGE__]->check($_) && $_->is_absolute },
                                            message    => sub { "$_ ain't an absolute resource identifier" },
                                           );
my $stringified_absolute_reference = "Type::Tiny"->new(
                                                       name       => "StringifiedAbsoluteResourceIdentifier",
                                                       constraint => sub { Str->check($_) && $_CALLER->can('new') && $absolute_reference->check($_CALLER->new($_)) },
                                                       message    => sub { "$_ ain't a stringified absolute resource identifier" },
                                                      );
our $check1 = compile(StringLike|ArrayRef, Maybe[$schemelike|$absolute_reference|$stringified_absolute_reference]);
our $check2 = compile(Str, Bytes, Maybe[Int]);

sub _BUILDARGS {
  my $class = shift;

  my ($first, $scheme) = $check1->($_[0], $_[1]);  # So that there always two parameters, even if 2nd is undef
  #
  # If first is an array ref, it must have at least two arguments pushed into decode()
  # - First is Str (encoding)
  # - Second is Bytes (bytes)
  # - Eventual third is Int (decode option)
  #
  my $input;
  if (ArrayRef->check($first)) {
    my ($encoding, $bytes, $opt) = $check2->(@{$first});
    #
    # Default, is not provided, is FB_CROAK
    #
    $opt //= Encode::FB_CROAK;
    $input = decode($encoding, $bytes, $opt);
  } else {
    $input = "$first";  # Eventual stringification
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
  $args->{scheme} = $scheme if (! Undef->check($scheme));
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
    }
  }
  #
  # else _generic: may fail unless URI_COMPAT
  #
  if (! $self) {
    try {
      my $subclass = sprintf('%s::%s', $class, '_generic');
      use_module($subclass);
      $self = $subclass->new($input);
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
    #
    # Used only when input is relative
    #
    if ($self->is_relative) {
    }
  }

  $self
}

1;
