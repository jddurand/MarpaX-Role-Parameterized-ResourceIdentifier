use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::_top;

# ABSTRACT: Internationalized Resource Identifier (IRI) : _top implementation

# VERSION

# AUTHORITY

#
# This is not really a role, because we want to have full controle over
# what new returns
#
use Carp qw/croak/;
use Encode qw/decode/;
use MarpaX::Role::Parameterized::ResourceIdentifier::Setup;
use MarpaX::Role::Parameterized::ResourceIdentifier::Types -all;
use Module::Runtime qw/use_module/;
use Try::Tiny;
use Type::Params qw/compile/;
use Types::Standard -all;
use Types::TypeTiny qw/StringLike/;
use Types::Encodings qw/Bytes/;
use constant  { TRUE => !!1 };

our $setup = MarpaX::Role::Parameterized::ResourceIdentifier::Setup->new;
our $check = compile(StringLike|HashRef, Maybe[Str]);

my $_CALLER = undef;

sub import { $_CALLER = caller }

sub BUILDARGS {
  my $class = shift;
  my ($first, $scheme) = $check->($_[0], $_[1]);
  #
  # If first is a HashRef ref, it must have at least two keys pushed into decode():
  # - octets          Bytes (bytes)
  # - encoding        Str (encoding)
  # - decode_strategy Maybe[Int] (decode option)
  # or
  # - input
  # where input have precedence
  #
  # It may also have:
  # - idn
  # - nfc
  # - ... whatever - it is kepts as it
  #
  my $input;
  my %rest = ();
  if (HashRef->check($first)) {
    if (exists($first->{input})) {
      croak 'input must do StringLike' unless StringLike->check($first->{input});
      my $thisinput = delete($first->{input});
      $input = "$thisinput";   # Eventual stringification
    } else {
      croak 'octets must do Bytes' unless Bytes->check($first->{octets});
      croak 'encoding must do Str' unless Str->check($first->{encoding});
      #
      # octets, encoding and decode_strategy are kept. encoding in particular
      # will be used in the IRI case for as_uri
      #
      my $octets          = $first->{octets};
      my $encoding        = $first->{encoding};
      #
      # Encode::encode will croak by itself if decode_strategy is not ok
      #
      my $decode_strategy = $first->{decode_strategy} // Encode::FB_CROAK;
      $input = decode($encoding, $octets, $decode_strategy);
    }
    %rest = %{$first};
  } else {
    $input = "$first";  # Eventual stringification
  }
  if ($setup->uri_compat) {
    #
    # Copy from URI:
    # Get rid of potential wrapping
    #
    $input =~ s/^<(?:URL:)?(.*)>$/$1/;
    $input =~ s/^"(.*)"$/$1/;
    $input =~ s/^\s+//;
    $input =~ s/\s+$//;
  }
  my $args = { input => $input, %rest };
  if (! $MarpaX::Role::Parameterized::ResourceIdentifier::Role::_top::inherited_from_child) {
    $args->{scheme} = $scheme if ! Undef->check($scheme);
  }

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

1;
