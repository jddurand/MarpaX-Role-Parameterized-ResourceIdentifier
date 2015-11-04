use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::_generic;

# ABSTRACT: Resource Identifier: Generic syntax semantics role

# VERSION

# AUTHORITY

use Moo::Role;
use MooX::Role::Logger;
use Types::Standard -all;
#
# Arguments of every callback:
# my ($self, $field, $value, $lhs) = @_;
#
# --------------------------------------------
# http://tools.ietf.org/html/rfc3987
# --------------------------------------------
#
# 3.1.  Mapping of IRIs to URIs
#
# ./.. Systems accepting IRIs MAY convert the ireg-name component of an IRI
#      as follows (before step 2 above) for schemes known to use domain
#      names in ireg-name, if the scheme definition does not allow
#      percent-encoding for ireg-name:
#
#      Replace the ireg-name part of the IRI by the part converted using the
#      ToASCII operation specified in section 4.1 of [RFC3490] on each
#      dot-separated label, and by using U+002E (FULL STOP) as a label
#      separator, with the flag UseSTD3ASCIIRules set to TRUE, and with the
#      flag AllowUnassigned set to FALSE for creating IRIs and set to TRUE
#      otherwise.

around build_uri_converter => sub {
  my ($orig, $self) = (shift, shift);

  my $rc = $self->$orig(@_);
  if ($self->reg_name_is_domain_name) {
    $rc->{reg_name} = sub {
      local $MarpaX::Role::Parameterized::ResourceIdentifier::Role::_generic::AllowUnassigned = 1,
      goto &_domain_to_ascii
    }
  }
  $rc
};

around build_iri_converter => sub {
  my ($orig, $self) = (shift, shift);

  my $rc = $self->$orig(@_);
  if ($self->reg_name_is_domain_name) {
    $rc->{reg_name} = sub {
      local $MarpaX::Role::Parameterized::ResourceIdentifier::Role::_generic::AllowUnassigned = 0,
      goto &_domain_to_ascii
    }
  }
  $rc
};

around build_case_normalizer => sub {
  my ($orig, $self) = (shift, shift);
  my $rc = $self->$orig(@_);
  # --------------------------------------------
  # http://tools.ietf.org/html/rfc3987
  # --------------------------------------------
  #
  # 5.3.2.1.  Case Normalization
  #
  # When an IRI uses components of the generic syntax, the component
  # syntax equivalence rules always apply; namely, that the scheme and
  # US-ASCII only host are case insensitive and therefore should be
  # normalized to lowercase.
  #
  $rc->{scheme} = sub { lc $_[2] };
  $rc->{host}   = sub { $_[2] =~ tr/\0-\x7f//c ? $_[2] : lc($_[2]) };
  $rc
};

around build_scheme_based_normalizer => sub {
  my ($orig, $self) = (shift, shift);
  my $rc = $self->$orig(@_);
  # --------------------------------------------
  # http://tools.ietf.org/html/rfc3987
  # --------------------------------------------
  #
  # 5.3.3.  Scheme-Based Normalization
  #
  # In general, an IRI that uses the generic syntax for authority with an
  # empty path should be normalized to a path of "/".
  #
  $rc->{path} = sub { length($_[2]) ? $_[2] : '/' };
  #
  # Likewise, an
  # explicit ":port", for which the port is empty or the default for the
  # scheme, is equivalent to one where the port and its ":" delimiter are
  # elided and thus should be removed by scheme-based normalization
  #
  if (! Undef->check($self->default_port)) {
    my $default_port= quotemeta($self->default_port);
    $rc->{authority} = sub { $_[2] =~ /:$default_port?\z/ ? substr($_[2], 0, $-[0]) : $_[2] }
  }
  $rc
};

sub _domain_to_ascii {
  #
  # Arguments: ($self, $field, $value, $lhs) = @_
  #
  my $self = $_[0];
  my $rc = $_[2];
  try {
    $rc = domain_to_ascii($rc, UseSTD3ASCIIRules => 1, AllowUnassigned => $MarpaX::Role::Parameterized::ResourceIdentifier::Role::_generic::AllowUnassigned)
  } catch {
    $self->_logger->warnf('%s', $_);
    return
  };
  $rc
}

1;
