use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::_common;

# ABSTRACT: Resource Identifier: Common syntax semantics

# VERSION

# AUTHORITY

use Encode qw/encode/;
use MarpaX::RFC::RFC3629;
use Moo::Role;
use MooX::Role::Logger;
use Unicode::Normalize qw/normalize/;
use Types::Standard -all;
use Try::Tiny;
#
# Arguments of every callback:
# my ($self, $field, $value, $lhs) = @_;
#
around build_case_normalizer => sub {
  my ($orig, $self) = (shift, shift);
  my $rc = $self->$orig(@_);
  #
  # --------------------------------------------
  # http://tools.ietf.org/html/rfc3987
  # --------------------------------------------
  #
  # 5.3.2.1.  Case Normalization
  #
  # For all IRIs, the hexadecimal digits within a percent-encoding
  # triplet (e.g., "%3a" versus "%3A") are case-insensitive and therefore
  # should be normalized to use uppercase letters for the digits A - F.
  #
  $rc->{$self->pct_encoded} = sub { uc $_[2] } if (! Undef->check($self->pct_encoded));
  $rc
};

around build_character_normalizer => sub {
  my ($orig, $self) = (shift, shift);
  my $rc = $self->$orig(@_);
  #
  # --------------------------------------------
  # http://tools.ietf.org/html/rfc3987
  # --------------------------------------------
  #
  # 5.3.2.2.  Character Normalization
  #
  # [The exceptions are] conversion
  # from a non-digital form, and conversion from a non-UCS-based
  # character encoding to a UCS-based character encoding. In these cases,
  # NFC or a normalizing transcoder using NFC MUST be used for
  # interoperability.
  #
  $rc->{''} = sub { normalize('C',  $_[2]) } if (! $self->is_character_normalized);
  $rc
};

around build_percent_encoding_normalizer => sub {
  my ($orig, $self) = (shift, shift);
  my $rc = $self->$orig(@_);
  #
  # --------------------------------------------
  # http://tools.ietf.org/html/rfc3987
  # --------------------------------------------
  #
  # 5.3.2.3.  Percent-Encoding Normalization
  #
  # ./.. IRIs should be normalized by decoding any
  # percent-encoded octet sequence that corresponds to an unreserved
  # character, as described in section 2.3 of [RFC3986].
  #
  if (! Undef->check($self->pct_encoded)) {
    $rc->{$self->pct_encoded} = sub {
      my $value = $_[2];
      #
      # Global unescape
      #
      my $unescaped_ok = 1;
      my $unescaped;
      try {
        my $octets = '';
        while ($value =~ m/(?<=%)[^%]+/gp) {
          $octets .= chr(hex(${^MATCH}))
        }
        $unescaped = MarpaX::RFC::RFC3629->new($octets)->output
      } catch {
        $self->_logger->warnf('%s', $_) for split(/\n/, "$_");
        $unescaped_ok = 0;
        return
      };
      #
      # And keep only characters in the unreserved set
      #
      if ($unescaped_ok) {
        my $new_value = '';
        my $position_in_original_rc = 0;
        my $unreserved = $self->unreserved;
        foreach (split('', $unescaped)) {
          my $length_of_encoded_in_original_rc;
          try {
            my $character = $_;
            my $re_encoded = join('', map { '%' . uc(unpack('H2', $_)) } split(//, encode('UTF-8', $character, Encode::FB_CROAK)));
            $length_of_encoded_in_original_rc = length($re_encoded);
          } catch {
            $self->_logger->warnf('%s', $_) for split(/\n/, "$_");
          };
          if (! defined($length_of_encoded_in_original_rc)) {
            $unescaped_ok = 0;
            last;
          }
          if ($_ =~ $unreserved) {
            $new_value .= $_;
          } else {
            $new_value = substr($value, $position_in_original_rc, $length_of_encoded_in_original_rc);
          }
          $position_in_original_rc += $length_of_encoded_in_original_rc;
        }
        $value = $new_value if ($unescaped_ok);
      }
      $value
    };
  }
  $rc
};

with 'MarpaX::Role::Parameterized::ResourceIdentifier::Role::BUILDARGS';

1;
