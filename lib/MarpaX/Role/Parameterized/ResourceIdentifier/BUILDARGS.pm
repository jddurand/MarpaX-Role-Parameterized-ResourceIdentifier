use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::BUILDARGS;

# ABSTRACT: BUILDARGS role for Resource Identifiers as per RFC3986 and RFC3987

# VERSION

# AUTHORITY

use Carp qw/croak/;
use Class::Method::Modifiers qw/install_modifier/;
use Encode qw/decode/;
use MarpaX::Role::Parameterized::ResourceIdentifier::Setup;
use MarpaX::Role::Parameterized::ResourceIdentifier::Types -all;
use Moo::Role;
use MooX::Role::Parameterized;
use Type::Params qw/compile/;
use Types::Standard -all;
use Types::TypeTiny qw/StringLike/;
use Types::Encodings qw/Bytes/;

our $setup    = MarpaX::Role::Parameterized::ResourceIdentifier::Setup->instance;

#
# This role is consumed by _top.pm and _common.pm. Take care: _common is NOT inheriting
# from _top.
#
# The "new" signature is common between all implementations:
# _top    is  (StringLike|HashRef, Maybe[SchemeLike|AbsoluteReference|StringifiedAbsoluteReference])
# _others are (StringLike|HashRef, Maybe[Str])
#

our $check_top    = compile(StringLike|HashRef, Maybe[SchemeLike|AbsoluteReference|StringifiedAbsoluteReference]);
our $check_others = compile(StringLike|HashRef, Maybe[Str]);

role {
  my $params = shift;

  # -----------------------
  # Sanity checks on params
  # -----------------------
  my %PARAMS = ();
  map { $PARAMS{$_} = $params->{$_} } qw/whoami type/;
  #
  # We will not insert methods in the role but in the calling package
  #
  croak 'whoami must exist and do Str' unless Str->check($PARAMS{whoami});
  my $whoami = $PARAMS{whoami};
  #
  # And this depend on its type: Top of NotTop
  #
  croak 'type must exist and do Enum[qw/Top NotTop/]' unless defined($PARAMS{type}) && grep {$_ eq $PARAMS{type}} qw/Top NotTop/;
  my $type = $PARAMS{type};
  #
  # We require a name for the second argument
  #
  croak "[$type] second_argument must exist and do Str" unless Str->check($params->{second_argument});
  my $second_argument = $params->{second_argument};
  my $check = $type eq 'Top' ? $check_top : $check_others;
  #
  # This is a bit vicious: we are installing BUILDARGS that is a Moo builtin method when
  # the caller is doing "use Moo". If at this precise compile time, Moo does not see
  # BUILDARGS, it will generate one.
  # So depending on where is placed the "use Moo" we have to do a fresh or around
  #
  my $buildargs_sub = sub {
    my $class = shift;
    my ($first, $second) = $check->($_[0], $_[1]);

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
        croak 'input must do Str' unless StringLike->check($first->{input});
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
    $args->{$second_argument} = $second if (! Undef->check($second));

    $args
  };
  my $can_BUILDARGS = $whoami->can('BUILDARGS');
  if ($can_BUILDARGS) {
    my $around;
    croak "[$type] $whoami must have an 'around' method (did you forgot to load Moo ?)" unless CodeRef->check($around = $whoami->can('around'));
    &$around(BUILDARGS => sub { my ($orig, $self) = (shift, shift); $self->$buildargs_sub(@_) });
  } else {
    install_modifier($whoami, 'fresh', BUILDARGS => $buildargs_sub );
  }
};

1;
