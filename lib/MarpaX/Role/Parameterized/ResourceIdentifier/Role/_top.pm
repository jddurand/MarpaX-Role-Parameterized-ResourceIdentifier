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
use Type::Params qw/compile/;
use Types::Standard -all;
use Types::TypeTiny qw/StringLike/;
use Types::Encodings qw/Bytes/;
use constant  { TRUE => !!1 };

my $_CALLER = undef;

sub import { $_CALLER = caller }

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
our $check2 = compile(Str, Bytes, Maybe[Int], Maybe[Bool], Maybe[Bool]);

sub _BUILDARGS {
  my $class = shift;

  my ($first, $scheme) = $check1->($_[0], $_[1]);  # So that there always two parameters, even if 2nd is undef
  #
  # If first is a HashRef ref, it must have at least two keys pushed into decode():
  # - octets          Bytes (bytes)
  # - encoding        Str (encoding)
  # - decode_strategy Maybe[Int] (decode option)
  # It may also have:
  # - idn
  # - nfc
  # - ... whatever - it is kepts as it
  #
  my $input;
  my %rest = ();
  if (HashRef->check($first)) {
    croak 'octets key must exist' if (! exists($first->{octets}));
    croak 'encoding key must exist' if (! exists($first->{encoding}));

    my $octets          = delete($first->{octets});
    my $encoding        = delete($first->{encoding});
    my $decode_strategy = delete($first->{decode_strategy}) // Encode::FB_CROAK;
    %rest = %{$first};

    $input = decode($encoding, $octets, $decode_strategy);
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
  my $args = { input => $input, %rest };
  $args->{scheme} = $scheme if (! Undef->check($scheme));
  #
  # Return arguments in a hash ref a per the spec
  #
  $args
}

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
  my $args = $class->_BUILDARGS(@_);
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
      # Per def $scheme is passing $schemelike|$absolute_reference|$stringified_absolute_reference
      #
      my $real_scheme;
      if ($schemelike->check($scheme)) {
        $real_scheme = $scheme;
      } elsif ($absolute_reference->check($scheme)) {
        $real_scheme = $scheme->scheme;
      } elsif ($stringified_absolute_reference->check($scheme)) {
        $real_scheme = $_CALLER->new($scheme)->scheme;
      } else {
        croak 'Impossible case';
      }
      $self = $class->_new_from_specific($real_scheme, $input) // $self;
    }
  }

  $self
}

1;
