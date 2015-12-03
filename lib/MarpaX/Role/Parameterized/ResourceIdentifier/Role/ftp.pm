use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::ftp;

# ABSTRACT: Resource Identifier: fp syntax semantics common overrides role

# VERSION

# AUTHORITY

use Moo::Role;

around default_port => sub { 21 };

around path => sub {
  my ($orig, $self) = (shift, shift);
  $self->path_query(@_)
};

around user => sub {
  my ($orig, $self) = (shift, shift);
  my $user = $self->$orig(@_);
  $user = 'anonymous' unless defined $user;
  $user
};

around password => sub {
  my ($orig, $self) = (shift, shift);
  my $password = $self->$orig(@_);
  unless (defined $password) {
    my $user = $self->user;
    if ($user eq 'anonymous' || $user eq 'ftp') {
      # anonymous ftp login password
      # If there is no ftp anonymous password specified
      # then we'll just use 'anonymous@'
      # We don't try to send the read e-mail address because:
      # - We want to remain anonymous
      # - We want to stop SPAM
      # - We don't want to let ftp sites to discriminate by the user,
      #   host, country or ftp client being used.
      $password = 'anonymous@';
    }
  }
  $password
};

1;
