"use strict";
(self["webpackChunkgame"] = self["webpackChunkgame"] || []).push([
  [752],
  {
    6276: function (t, i, e) {
      e.d(i, {
        A: function () {
          return B;
        },
      });
      var o = function () {
          var t = this,
            i = t.$createElement,
            e = t._self._c || i;
          return t.changingWord && t.changeWordHomographOptions.length > 0
            ? e(
                "div",
                [
                  e(
                    "b-button",
                    {
                      attrs: {
                        type: "is-ghost",
                        "icon-left": "arrow-left",
                        "icon-pack": "mdi",
                      },
                      on: {
                        click: function (i) {
                          (i.preventDefault(), (t.changingWord = null));
                        },
                      },
                    },
                    [t._v(" Back ")],
                  ),
                  e("h1", [
                    t._v(
                      ' Choose variant of word "' +
                        t._s(t.changingWord.dictionary.word) +
                        '" ',
                    ),
                  ]),
                  e("WordVariantSelector", {
                    attrs: {
                      homographs: t.changeWordHomographOptions,
                      "custom-icon-size": "",
                      word: t.changingWord.dictionary.word,
                      locale: t.changingWord.dictionary.locale,
                      "dictionary-id": t.changingWord.dictionary.id,
                      "is-equal": t.isEqual,
                      "play-sound-for-phoneme": t.playSoundForPhoneme,
                      "play-dictionary-audio": t.speakDictionary,
                    },
                    on: { "selected-dictionary": t.definitionSelected },
                  }),
                ],
                1,
              )
            : t.addWordHomographOptions.length > 0
              ? e(
                  "div",
                  [
                    e(
                      "b-button",
                      {
                        attrs: {
                          "icon-left": "arrow-left",
                          "icon-pack": "mdi",
                        },
                        on: {
                          click: function (i) {
                            (i.preventDefault(),
                              (t.addWordHomographOptions = []));
                          },
                        },
                      },
                      [t._v(" Back ")],
                    ),
                    e("h1", [
                      t._v(
                        " " +
                          t._s(
                            t.addWordHomographOptions.find(function (i) {
                              return i.word === t.addWordHomographExact;
                            }) ||
                              (t.listData.words || []).find(function (i) {
                                return (
                                  (i.dictionary.parent_word || i.dictionary)
                                    .word === t.addWordHomographExact
                                );
                              })
                              ? 'Choose variant of word "' +
                                  t.addWordHomographExact +
                                  '"'
                              : "Word not found",
                          ) +
                          " ",
                      ),
                    ]),
                    e("WordVariantSelector", {
                      attrs: {
                        homographs: t.addWordHomographOptions,
                        "custom-icon-size": "",
                        word: t.addWordHomographExact,
                        "allow-create": t.addWordHomographAllowCreate,
                        locale: t.listData.locale,
                        "is-equal": t.isEqual,
                        "play-sound-for-phoneme": t.playSoundForPhoneme,
                        "play-dictionary-audio": t.speakDictionary,
                      },
                      on: {
                        "selected-dictionary": function (i) {
                          return t.doAddWord({
                            text: i.word,
                            dictionary_id: i.id,
                          });
                        },
                        "new-word": t.doAddWord,
                      },
                    }),
                  ],
                  1,
                )
              : t.listData
                ? e(
                    "div",
                    [
                      e(
                        "b-button",
                        {
                          attrs: {
                            type: "is-ghost",
                            "icon-left": "arrow-left",
                            "icon-pack": "mdi",
                          },
                          on: {
                            click: function (i) {
                              return (i.preventDefault(), t.$emit("clear"));
                            },
                          },
                        },
                        [t._v(" Back ")],
                      ),
                      e(
                        "div",
                        { staticClass: "is-pulled-right" },
                        [
                          t.reportableList
                            ? e(
                                "button",
                                {
                                  staticClass: "button is-info",
                                  staticStyle: { "margin-left": "10px" },
                                  on: { click: t.showReportListModal },
                                },
                                [e("i", { staticClass: "fas fa-flag" })],
                              )
                            : t._e(),
                          t.isOwner
                            ? e(
                                "span",
                                { staticStyle: { "margin-left": "10px" } },
                                [
                                  e(
                                    "b-tooltip",
                                    {
                                      attrs: {
                                        type: "is-dark",
                                        label: "Add word",
                                        position: "is-bottom",
                                      },
                                    },
                                    [
                                      e(
                                        "button",
                                        {
                                          staticClass: "button is-primary",
                                          on: {
                                            click: function (i) {
                                              return (
                                                i.preventDefault(),
                                                t.addWord(i)
                                              );
                                            },
                                          },
                                        },
                                        [
                                          e("i", {
                                            staticClass: "fas fa-plus",
                                          }),
                                        ],
                                      ),
                                    ],
                                  ),
                                ],
                                1,
                              )
                            : e(
                                "span",
                                { staticStyle: { "margin-left": "10px" } },
                                [
                                  1 == t.listData.fav
                                    ? e(
                                        "a",
                                        {
                                          key: "fav1",
                                          staticClass: "button is-danger",
                                          attrs: { id: "fav1", href: "#" },
                                          on: {
                                            click: function (i) {
                                              return (
                                                i.preventDefault(),
                                                t.unFavourite()
                                              );
                                            },
                                          },
                                        },
                                        [
                                          e("i", {
                                            staticClass: "fas fa-heart",
                                          }),
                                        ],
                                      )
                                    : e(
                                        "a",
                                        {
                                          key: "fav0",
                                          staticClass: "button is-danger",
                                          attrs: { id: "fav0", href: "#" },
                                          on: {
                                            click: function (i) {
                                              return (
                                                i.preventDefault(),
                                                t.favourite()
                                              );
                                            },
                                          },
                                        },
                                        [
                                          e("i", {
                                            staticClass: "far fa-heart",
                                          }),
                                        ],
                                      ),
                                ],
                              ),
                          e(
                            "b-tooltip",
                            {
                              attrs: {
                                type: "is-dark",
                                label: "Play list",
                                position: "is-bottom",
                              },
                            },
                            [
                              e(
                                "button",
                                {
                                  staticClass: "button is-success",
                                  staticStyle: { "margin-left": "10px" },
                                  on: {
                                    click: function (i) {
                                      return (i.preventDefault(), t.playList());
                                    },
                                  },
                                },
                                [e("i", { staticClass: "fas fa-play" })],
                              ),
                            ],
                          ),
                        ],
                        1,
                      ),
                      e("h1", [t._v(t._s(t.listData.title))]),
                      e("p", [
                        e(
                          "a",
                          {
                            attrs: { href: "#" },
                            on: {
                              click: function (t) {
                                t.preventDefault();
                              },
                            },
                          },
                          [t._v("@" + t._s(t.listData.owner))],
                        ),
                        t._v(" "),
                        t.listData.scheme
                          ? e("span", { staticClass: "tag is-warning" }, [
                              t._v(
                                t._s(
                                  "en_US" === t.$store.state.user.locale
                                    ? "CURRICULUM"
                                    : "SCHEME",
                                ),
                              ),
                            ])
                          : t._e(),
                        t._v(" "),
                        t.listData.is_phonics
                          ? e("span", { staticClass: "tag is-success" }, [
                              t._v("PHONICS"),
                            ])
                          : t._e(),
                      ]),
                      e(
                        "p",
                        [
                          e("star-rating", {
                            attrs: {
                              "item-size": 28,
                              "active-color": "#ffdf00",
                              "border-color": "transparent",
                              spacing: -5,
                              "read-only": t.isOwner,
                              "show-rating": !1,
                              inline: !0,
                            },
                            on: { "rating-selected": t.sendRating },
                            model: {
                              value: t.listData.rating,
                              callback: function (i) {
                                t.$set(t.listData, "rating", i);
                              },
                              expression: "listData.rating",
                            },
                          }),
                        ],
                        1,
                      ),
                      e(
                        "b-table",
                        {
                          attrs: {
                            loading: t.loading,
                            data: t.wordData.items,
                            paginated: !0,
                            "per-page": 10,
                            total: t.wordData.total,
                            "current-page": t.currentPage,
                            "pagination-simple": !1,
                            "backend-pagination": !0,
                            "backend-sorting": !0,
                            "mobile-cards": !1,
                            striped: !0,
                          },
                          on: {
                            "update:data": function (i) {
                              return t.$set(t.wordData, "items", i);
                            },
                            "update:currentPage": function (i) {
                              t.currentPage = i;
                            },
                            "update:current-page": function (i) {
                              t.currentPage = i;
                            },
                            "page-change": t.pageChanged,
                            sort: t.onSort,
                          },
                        },
                        [
                          e("b-table-column", {
                            attrs: {
                              field: "text",
                              label: "Word",
                              sortable: "",
                            },
                            scopedSlots: t._u([
                              {
                                key: "default",
                                fn: function (i) {
                                  return [
                                    t._v(
                                      " " + t._s(i.row.dictionary.word) + " ",
                                    ),
                                  ];
                                },
                              },
                            ]),
                          }),
                          t.isOwner
                            ? e("b-table-column", {
                                attrs: { field: "actions", label: "" },
                                scopedSlots: t._u(
                                  [
                                    {
                                      key: "default",
                                      fn: function (i) {
                                        return [
                                          e(
                                            "b-tooltip",
                                            {
                                              staticClass: "is-pulled-right",
                                              attrs: {
                                                label: "Delete word",
                                                type: "is-dark",
                                              },
                                            },
                                            [
                                              e(
                                                "button",
                                                {
                                                  staticClass:
                                                    "button is-danger delete-word-button",
                                                  on: {
                                                    click: function (e) {
                                                      return (
                                                        e.preventDefault(),
                                                        t.deleteWord(i.row)
                                                      );
                                                    },
                                                  },
                                                },
                                                [
                                                  e("i", {
                                                    staticClass: "fa fa-times",
                                                  }),
                                                ],
                                              ),
                                            ],
                                          ),
                                          e(
                                            "b-tooltip",
                                            {
                                              staticClass: "is-pulled-right",
                                              attrs: {
                                                label: "Change word variant",
                                                type: "is-dark",
                                              },
                                            },
                                            [
                                              e(
                                                "button",
                                                {
                                                  staticClass:
                                                    "button is-link ",
                                                  on: {
                                                    click: function (e) {
                                                      return (
                                                        e.preventDefault(),
                                                        t.changeWordVariant(
                                                          i.row,
                                                        )
                                                      );
                                                    },
                                                  },
                                                },
                                                [
                                                  e("i", {
                                                    staticClass:
                                                      "mdi mdi-swap-horizontal-bold",
                                                  }),
                                                ],
                                              ),
                                            ],
                                          ),
                                        ];
                                      },
                                    },
                                  ],
                                  null,
                                  !1,
                                  826723202,
                                ),
                              })
                            : t._e(),
                          e("template", { slot: "empty" }, [
                            e("section", { staticClass: "section" }, [
                              e(
                                "div",
                                {
                                  staticClass:
                                    "content has-text-grey has-text-centered",
                                },
                                [
                                  e(
                                    "p",
                                    [
                                      e("b-icon", {
                                        attrs: {
                                          "custom-class": "far",
                                          pack: "fa",
                                          icon: "frown",
                                          size: "is-large",
                                        },
                                      }),
                                    ],
                                    1,
                                  ),
                                  e("p", [t._v("Nothing here.")]),
                                ],
                              ),
                            ]),
                          ]),
                        ],
                        2,
                      ),
                      t.showReportList
                        ? e("ReportListModal", {
                            attrs: { id: { ident: t.listData.ident } },
                            on: { close: t.hideReportListModal },
                          })
                        : t._e(),
                    ],
                    1,
                  )
                : e(
                    "div",
                    { staticClass: "has-text-centered section" },
                    [
                      e("b-icon", {
                        attrs: {
                          pack: "fas",
                          icon: "sync-alt",
                          size: "is-large",
                          "custom-class": "fa-spin",
                        },
                      }),
                    ],
                    1,
                  );
        },
        s = [],
        a =
          (e(44114),
          e(26910),
          e(18111),
          e(22489),
          e(20116),
          e(61701),
          e(33110),
          e(27495),
          e(25440),
          e(42762),
          e(73040)),
        r = (e(64924), e(78626)),
        n = e(31552),
        d = e(61484),
        l = function () {
          var t = this,
            i = t.$createElement,
            e = t._self._c || i;
          return e("section", [
            e(
              "div",
              { staticClass: "wrapper" },
              [
                t.orderedHomographs.find(function (i) {
                  return i.word === t.word;
                })
                  ? t._e()
                  : e(
                      "b-notification",
                      { attrs: { type: "is-warning", closable: !1 } },
                      [
                        e(
                          "div",
                          [
                            t.allowCreate
                              ? e(
                                  "b-button",
                                  {
                                    staticStyle: {
                                      "margin-left": "20px",
                                      float: "right",
                                    },
                                    attrs: {
                                      type: "is-link",
                                      "icon-left": "plus",
                                    },
                                    on: {
                                      click: function (i) {
                                        return t.$emit("new-word", t.word);
                                      },
                                    },
                                  },
                                  [
                                    t._v(
                                      ' Create new word "' +
                                        t._s(t.word) +
                                        '" ',
                                    ),
                                  ],
                                )
                              : t._e(),
                            e("span", {
                              domProps: {
                                innerHTML: t._s(t.wordNotFoundError),
                              },
                            }),
                          ],
                          1,
                        ),
                      ],
                    ),
                t._l(t.orderedHomographs, function (i, o) {
                  return e(
                    "div",
                    { key: i.id },
                    [
                      e(
                        "b-field",
                        {
                          staticClass: "definition-row",
                          class:
                            (o > 0 && null === i.parent_word
                              ? "divided-row"
                              : "") +
                            " " +
                            (t.selectedDefinition === i ? "selected" : "") +
                            " " +
                            (t.dictionaryMoreDetails === i ? "expanded" : ""),
                          attrs: { expanded: "" },
                        },
                        [
                          i.parent_word
                            ? e("b-icon", {
                                staticClass: "child-indicator",
                                attrs: {
                                  pack: "mdi",
                                  icon: "subdirectory-arrow-right",
                                  size: t.customIconSize,
                                },
                              })
                            : t._e(),
                          e(
                            "b-radio",
                            {
                              attrs: {
                                "native-value": i,
                                type: "is-info",
                                expanded: "",
                              },
                              model: {
                                value: t.selectedDefinition,
                                callback: function (i) {
                                  t.selectedDefinition = i;
                                },
                                expression: "selectedDefinition",
                              },
                            },
                            [
                              e("div", { staticClass: "columns" }, [
                                e(
                                  "div",
                                  { staticClass: "column is-2" },
                                  [
                                    i.image && i.image.thumbnailPath
                                      ? e("img", {
                                          staticClass: "definition-image",
                                          class: i.parent_word ? "child" : "",
                                          attrs: { src: i.image.thumbnailPath },
                                        })
                                      : e("b-icon", {
                                          staticClass: "definition-image",
                                          attrs: {
                                            "custom-class": i.parent_word
                                              ? "child"
                                              : "",
                                            size: "is-large",
                                            icon: "image-off",
                                            pack: "mdi",
                                          },
                                        }),
                                  ],
                                  1,
                                ),
                                e("div", { staticClass: "column is-9" }, [
                                  e(
                                    "div",
                                    {
                                      staticClass: "definition-row-body-header",
                                    },
                                    [
                                      e(
                                        "strong",
                                        {
                                          staticClass:
                                            "definition-row-body-header-word",
                                        },
                                        [t._v(t._s(i.word))],
                                      ),
                                      e("b-icon", {
                                        staticClass:
                                          "definition-row-body-header-audio",
                                        attrs: {
                                          pack: "mdi",
                                          icon: "volume-high",
                                        },
                                        nativeOn: {
                                          click: function (e) {
                                            return (
                                              e.preventDefault(),
                                              t.playDictionaryAudio(i)
                                            );
                                          },
                                        },
                                      }),
                                      e(
                                        "span",
                                        {
                                          staticClass:
                                            "definition-row-body-header-owner",
                                        },
                                        [
                                          t._v(
                                            " @" + t._s(i.owner_username) + " ",
                                          ),
                                        ],
                                      ),
                                      e(
                                        "b-tooltip",
                                        {
                                          staticClass:
                                            "dictionary-edit-type-icon",
                                          attrs: {
                                            type: "is-warning",
                                            label:
                                              null === i.parent_word
                                                ? i.approved
                                                  ? "Official word"
                                                  : "Standard word"
                                                : "Custom word",
                                            position: "is-bottom",
                                          },
                                        },
                                        [
                                          e("b-icon", {
                                            attrs: {
                                              icon:
                                                null === i.parent_word
                                                  ? "beehive-outline"
                                                  : "beehive-off-outline",
                                              type:
                                                null === i.parent_word
                                                  ? i.approved
                                                    ? "is-success"
                                                    : "is-warning"
                                                  : "is-number",
                                              pack: "mdi",
                                              size: "is-small",
                                            },
                                          }),
                                        ],
                                        1,
                                      ),
                                    ],
                                    1,
                                  ),
                                  e(
                                    "div",
                                    {
                                      staticClass: "definition-row-body-footer",
                                    },
                                    [
                                      i.definitions.length > 0
                                        ? e(
                                            "ul",
                                            { staticClass: "definition-list" },
                                            t._l(
                                              i.definitions,
                                              function (i, o) {
                                                return e(
                                                  "li",
                                                  { key: o },
                                                  [
                                                    e(
                                                      "b-tag",
                                                      {
                                                        staticClass:
                                                          "definition-class-tag",
                                                        attrs: {
                                                          type: "is-dark",
                                                        },
                                                      },
                                                      [
                                                        t._v(
                                                          " " +
                                                            t._s(i.class) +
                                                            " ",
                                                        ),
                                                      ],
                                                    ),
                                                    t._v(
                                                      " - " +
                                                        t._s(i.definition) +
                                                        " ",
                                                    ),
                                                  ],
                                                  1,
                                                );
                                              },
                                            ),
                                            0,
                                          )
                                        : e("span"),
                                    ],
                                  ),
                                ]),
                                e(
                                  "div",
                                  { staticClass: "column is-1" },
                                  [
                                    e("b-icon", {
                                      staticClass: "is-pulled-right",
                                      attrs: {
                                        pack: "mdi",
                                        icon:
                                          t.dictionaryMoreDetails === i
                                            ? "chevron-up"
                                            : "chevron-down",
                                      },
                                      nativeOn: {
                                        click: function (e) {
                                          return (
                                            e.preventDefault(),
                                            t.moreDetailsClicked(i)
                                          );
                                        },
                                      },
                                    }),
                                  ],
                                  1,
                                ),
                              ]),
                            ],
                          ),
                        ],
                        1,
                      ),
                      e(
                        "b-collapse",
                        { attrs: { open: t.dictionaryMoreDetails === i } },
                        [
                          t.dictionaryMoreDetails
                            ? e(
                                "div",
                                { staticClass: "content details-wrapper" },
                                [
                                  e("div", { staticClass: "columns" }, [
                                    e("div", { staticClass: "column is-6" }, [
                                      e(
                                        "h6",
                                        [
                                          t._v(" Sentences "),
                                          e(
                                            "b-tooltip",
                                            {
                                              attrs: {
                                                type: "is-warning",
                                                label: t.doesFieldMatchRoot(
                                                  t.dictionaryMoreDetails,
                                                  "sentences",
                                                )
                                                  ? i.approved
                                                    ? "Using official definition"
                                                    : "Using standard definition"
                                                  : "Using custom definition",
                                                position: "is-right",
                                              },
                                            },
                                            [
                                              e("b-icon", {
                                                attrs: {
                                                  pack: "mdi",
                                                  size: "is-small",
                                                  type: t.doesFieldMatchRoot(
                                                    t.dictionaryMoreDetails,
                                                    "sentences",
                                                  )
                                                    ? i.approved
                                                      ? "is-success"
                                                      : "is-warning"
                                                    : "is-number",
                                                  icon: t.doesFieldMatchRoot(
                                                    t.dictionaryMoreDetails,
                                                    "sentences",
                                                  )
                                                    ? "beehive-outline"
                                                    : "beehive-off-outline",
                                                },
                                              }),
                                            ],
                                            1,
                                          ),
                                        ],
                                        1,
                                      ),
                                      e(
                                        "ul",
                                        { staticClass: "definition-list" },
                                        t._l(
                                          t.dictionaryMoreDetails.sentences,
                                          function (i, o) {
                                            return e("li", {
                                              key: o,
                                              domProps: {
                                                innerHTML: t._s(
                                                  "&#8220;" +
                                                    i.replace(
                                                      "*",
                                                      "<strong>" +
                                                        t.dictionaryMoreDetails
                                                          .word +
                                                        "</strong>",
                                                    ) +
                                                    "&#8221;",
                                                ),
                                              },
                                            });
                                          },
                                        ),
                                        0,
                                      ),
                                    ]),
                                    e(
                                      "div",
                                      { staticClass: "column is-3" },
                                      [
                                        e(
                                          "h6",
                                          [
                                            t._v(" Common mistakes "),
                                            e(
                                              "b-tooltip",
                                              {
                                                attrs: {
                                                  type: "is-warning",
                                                  label: t.doesFieldMatchRoot(
                                                    t.dictionaryMoreDetails,
                                                    "errors",
                                                  )
                                                    ? i.approved
                                                      ? "Using official definition"
                                                      : "Using standard definition"
                                                    : "Using custom definition",
                                                  position: "is-bottom",
                                                },
                                              },
                                              [
                                                e("b-icon", {
                                                  attrs: {
                                                    pack: "mdi",
                                                    size: "is-small",
                                                    type: t.doesFieldMatchRoot(
                                                      t.dictionaryMoreDetails,
                                                      "errors",
                                                    )
                                                      ? i.approved
                                                        ? "is-success"
                                                        : "is-warning"
                                                      : "is-number",
                                                    icon: t.doesFieldMatchRoot(
                                                      t.dictionaryMoreDetails,
                                                      "errors",
                                                    )
                                                      ? "beehive-outline"
                                                      : "beehive-off-outline",
                                                  },
                                                }),
                                              ],
                                              1,
                                            ),
                                          ],
                                          1,
                                        ),
                                        e(
                                          "b-taglist",
                                          t._l(
                                            t.dictionaryMoreDetails.errors,
                                            function (i, o) {
                                              return e(
                                                "b-tag",
                                                {
                                                  key: o,
                                                  attrs: { type: "is-danger" },
                                                },
                                                [t._v(" " + t._s(i) + " ")],
                                              );
                                            },
                                          ),
                                          1,
                                        ),
                                      ],
                                      1,
                                    ),
                                    e(
                                      "div",
                                      { staticClass: "column is-3" },
                                      [
                                        e(
                                          "h6",
                                          [
                                            t._v(" Morphemes "),
                                            e(
                                              "b-tooltip",
                                              {
                                                attrs: {
                                                  type: "is-warning",
                                                  label: t.doesFieldMatchRoot(
                                                    t.dictionaryMoreDetails,
                                                    "morphemes",
                                                  )
                                                    ? i.approved
                                                      ? "Using official definition"
                                                      : "Using standard definition"
                                                    : "Using custom definition",
                                                  position: "is-bottom",
                                                },
                                              },
                                              [
                                                e("b-icon", {
                                                  attrs: {
                                                    pack: "mdi",
                                                    size: "is-small",
                                                    type: t.doesFieldMatchRoot(
                                                      t.dictionaryMoreDetails,
                                                      "morphemes",
                                                    )
                                                      ? i.approved
                                                        ? "is-success"
                                                        : "is-warning"
                                                      : "is-number",
                                                    icon: t.doesFieldMatchRoot(
                                                      t.dictionaryMoreDetails,
                                                      "morphemes",
                                                    )
                                                      ? "beehive-outline"
                                                      : "beehive-off-outline",
                                                  },
                                                }),
                                              ],
                                              1,
                                            ),
                                          ],
                                          1,
                                        ),
                                        e(
                                          "b-taglist",
                                          t._l(
                                            t.dictionaryMoreDetails.morphemes,
                                            function (i, o) {
                                              return e(
                                                "b-tag",
                                                {
                                                  key: o,
                                                  attrs: { type: "is-link" },
                                                },
                                                [t._v(" " + t._s(i) + " ")],
                                              );
                                            },
                                          ),
                                          1,
                                        ),
                                      ],
                                      1,
                                    ),
                                  ]),
                                  e("div", { staticClass: "columns" }, [
                                    e("div", { staticClass: "column is-6" }, [
                                      e(
                                        "h6",
                                        [
                                          t._v(" Synonyms "),
                                          e(
                                            "b-tooltip",
                                            {
                                              attrs: {
                                                type: "is-warning",
                                                label: t.doesFieldMatchRoot(
                                                  t.dictionaryMoreDetails,
                                                  "synonyms",
                                                )
                                                  ? i.approved
                                                    ? "Using official definition"
                                                    : "Using standard definition"
                                                  : "Using custom definition",
                                                position: "is-right",
                                              },
                                            },
                                            [
                                              e("b-icon", {
                                                attrs: {
                                                  pack: "mdi",
                                                  size: "is-small",
                                                  type: t.doesFieldMatchRoot(
                                                    t.dictionaryMoreDetails,
                                                    "synonyms",
                                                  )
                                                    ? i.approved
                                                      ? "is-success"
                                                      : "is-warning"
                                                    : "is-number",
                                                  icon: t.doesFieldMatchRoot(
                                                    t.dictionaryMoreDetails,
                                                    "synonyms",
                                                  )
                                                    ? "beehive-outline"
                                                    : "beehive-off-outline",
                                                },
                                              }),
                                            ],
                                            1,
                                          ),
                                        ],
                                        1,
                                      ),
                                      e(
                                        "ul",
                                        { staticClass: "definition-list" },
                                        t._l(
                                          t.dictionaryMoreDetails.synonyms,
                                          function (i, o) {
                                            return e("li", { key: o }, [
                                              e(
                                                "span",
                                                {
                                                  staticClass:
                                                    "has-text-weight-bold",
                                                },
                                                [
                                                  t._v(
                                                    " " + t._s(i.word) + " ",
                                                  ),
                                                ],
                                              ),
                                              i.definitions[0]
                                                ? e("span", [
                                                    e(
                                                      "span",
                                                      {
                                                        staticClass:
                                                          "tag is-dark",
                                                      },
                                                      [
                                                        t._v(
                                                          t._s(
                                                            i.definitions[0]
                                                              .class,
                                                          ),
                                                        ),
                                                      ],
                                                    ),
                                                    t._v(
                                                      " " +
                                                        t._s(
                                                          i.definitions[0]
                                                            .definition,
                                                        ) +
                                                        " ",
                                                    ),
                                                  ])
                                                : t._e(),
                                            ]);
                                          },
                                        ),
                                        0,
                                      ),
                                    ]),
                                    e("div", { staticClass: "column is-6" }, [
                                      e(
                                        "h6",
                                        [
                                          t._v(" Antonyms "),
                                          e(
                                            "b-tooltip",
                                            {
                                              attrs: {
                                                type: "is-warning",
                                                label: t.doesFieldMatchRoot(
                                                  t.dictionaryMoreDetails,
                                                  "antonyms",
                                                )
                                                  ? i.approved
                                                    ? "Using official definition"
                                                    : "Using standard definition"
                                                  : "Using custom definition",
                                                position: "is-right",
                                              },
                                            },
                                            [
                                              e("b-icon", {
                                                attrs: {
                                                  pack: "mdi",
                                                  size: "is-small",
                                                  type: t.doesFieldMatchRoot(
                                                    t.dictionaryMoreDetails,
                                                    "antonyms",
                                                  )
                                                    ? i.approved
                                                      ? "is-success"
                                                      : "is-warning"
                                                    : "is-number",
                                                  icon: t.doesFieldMatchRoot(
                                                    t.dictionaryMoreDetails,
                                                    "antonyms",
                                                  )
                                                    ? "beehive-outline"
                                                    : "beehive-off-outline",
                                                },
                                              }),
                                            ],
                                            1,
                                          ),
                                        ],
                                        1,
                                      ),
                                      e(
                                        "ul",
                                        { staticClass: "definition-list" },
                                        t._l(
                                          t.dictionaryMoreDetails.antonyms,
                                          function (i, o) {
                                            return e("li", { key: o }, [
                                              e(
                                                "span",
                                                {
                                                  staticClass:
                                                    "has-text-weight-bold",
                                                },
                                                [
                                                  t._v(
                                                    " " + t._s(i.word) + " ",
                                                  ),
                                                ],
                                              ),
                                              i.definitions[0]
                                                ? e("span", [
                                                    e(
                                                      "span",
                                                      {
                                                        staticClass:
                                                          "tag is-dark",
                                                      },
                                                      [
                                                        t._v(
                                                          t._s(
                                                            i.definitions[0]
                                                              .class,
                                                          ),
                                                        ),
                                                      ],
                                                    ),
                                                    t._v(
                                                      " " +
                                                        t._s(
                                                          i.definitions[0]
                                                            .definition,
                                                        ) +
                                                        " ",
                                                    ),
                                                  ])
                                                : t._e(),
                                            ]);
                                          },
                                        ),
                                        0,
                                      ),
                                    ]),
                                  ]),
                                  e(
                                    "div",
                                    [
                                      e(
                                        "h6",
                                        [
                                          t._v(" Phonics "),
                                          e(
                                            "b-tooltip",
                                            {
                                              attrs: {
                                                type: "is-warning",
                                                label: t.doesFieldMatchRoot(
                                                  t.dictionaryMoreDetails,
                                                  "phonics",
                                                )
                                                  ? i.approved
                                                    ? "Using official definition"
                                                    : "Using standard definition"
                                                  : "Using custom definition",
                                                position: "is-right",
                                              },
                                            },
                                            [
                                              e("b-icon", {
                                                attrs: {
                                                  pack: "mdi",
                                                  size: "is-small",
                                                  type: t.doesFieldMatchRoot(
                                                    t.dictionaryMoreDetails,
                                                    "phonics",
                                                  )
                                                    ? i.approved
                                                      ? "is-success"
                                                      : "is-warning"
                                                    : "is-number",
                                                  icon: t.doesFieldMatchRoot(
                                                    t.dictionaryMoreDetails,
                                                    "phonics",
                                                  )
                                                    ? "beehive-outline"
                                                    : "beehive-off-outline",
                                                },
                                              }),
                                            ],
                                            1,
                                          ),
                                        ],
                                        1,
                                      ),
                                      t._l(
                                        t.dictionaryMoreDetails.phonics,
                                        function (i, o) {
                                          return e("PhonicsPairBlock", {
                                            key: o,
                                            attrs: {
                                              pair: i,
                                              locale:
                                                t.dictionaryMoreDetails.locale,
                                              "play-sound-for-phoneme":
                                                t.playSoundForPhoneme,
                                              symbol: t.symbolForPhoneme(
                                                i.phoneme,
                                                t.phonemesData,
                                              ),
                                            },
                                          });
                                        },
                                      ),
                                    ],
                                    2,
                                  ),
                                ],
                              )
                            : t._e(),
                        ],
                      ),
                    ],
                    1,
                  );
                }),
              ],
              2,
            ),
            e("footer", { staticClass: "modal-card-foot" }, [
              t.selectedDefinition
                ? e(
                    "button",
                    {
                      directives: [
                        {
                          name: "async",
                          rawName: "v-async",
                          value: function () {
                            return t.submit();
                          },
                          expression: "() => submit()",
                        },
                      ],
                      staticClass: "button is-link",
                      attrs: {
                        disabled: t.dictionaryId === t.selectedDefinition.id,
                      },
                    },
                    [t._v(" Use Definition ")],
                  )
                : t._e(),
            ]),
          ]);
        },
        c = [],
        h = e(91114),
        p = (e(62953), e(31635)),
        u = e(18657);
      e(41034);
      function g(t, i) {
        var e, o;
        return t && i
          ? null !==
              (e =
                null === (o = i.find((i) => i.code === t)) || void 0 === o
                  ? void 0
                  : o.ipa) && void 0 !== e
            ? e
            : "?"
          : null;
      }
      var f = e(43564),
        m = function () {
          var t = this,
            i = t.$createElement,
            e = t._self._c || i;
          return e(
            "section",
            [
              t._v(" " + t._s(t.label) + " "),
              t.personalDictionary
                ? e(
                    "b-tooltip",
                    {
                      attrs: {
                        type: "is-warning",
                        label: t.matchesRoot
                          ? "Your definition matches our official definition"
                          : "You have customised this definition",
                        position: "is-bottom",
                      },
                    },
                    [
                      e("b-icon", {
                        attrs: {
                          size: "is-small",
                          type: t.matchesRoot ? "is-success" : "is-number",
                          icon: t.matchesRoot
                            ? "beehive-outline"
                            : "beehive-off-outline",
                        },
                      }),
                    ],
                    1,
                  )
                : t._e(),
              t.hasChanged
                ? e(
                    "b-tooltip",
                    {
                      attrs: {
                        type: "is-warning",
                        label: "This field has pending changes",
                        position: "is-bottom",
                      },
                    },
                    [
                      e("b-icon", {
                        attrs: {
                          size: "is-small",
                          type: "is-dark",
                          icon: "pencil",
                        },
                      }),
                    ],
                    1,
                  )
                : t._e(),
              t.disabled
                ? t._e()
                : e(
                    "div",
                    { staticClass: "dictionary-label-actions" },
                    [
                      null !== t.addOption
                        ? e(
                            "b-tooltip",
                            {
                              attrs: {
                                type: "is-warning",
                                label: t.addOption,
                                position: "is-bottom",
                              },
                            },
                            [
                              e(
                                "button",
                                {
                                  staticClass: "button is-success is-small",
                                  attrs: {
                                    disabled: t.disabled,
                                    size: "is-small",
                                  },
                                  on: {
                                    click: function (i) {
                                      return t.$emit("add-clicked");
                                    },
                                  },
                                },
                                [e("i", { staticClass: "mdi mdi-plus" })],
                              ),
                            ],
                          )
                        : t._e(),
                      e(
                        "b-tooltip",
                        {
                          attrs: {
                            type: "is-warning",
                            label: "Undo pending changes",
                            position: "is-bottom",
                          },
                        },
                        [
                          e(
                            "button",
                            {
                              staticClass: "button is-small is-dark ",
                              attrs: { disabled: !t.hasChanged || t.disabled },
                              on: {
                                click: function (i) {
                                  return t.$emit("undo-pending");
                                },
                              },
                            },
                            [e("i", { staticClass: "mdi mdi-undo" })],
                          ),
                        ],
                      ),
                      t.personalDictionary
                        ? e(
                            "b-tooltip",
                            {
                              attrs: {
                                type: "is-warning",
                                label: "Restore official definition",
                                position: "is-bottom",
                              },
                            },
                            [
                              e(
                                "button",
                                {
                                  staticClass: "button is-small is-dark ",
                                  attrs: {
                                    disabled: t.matchesRoot || t.disabled,
                                  },
                                  on: {
                                    click: function (i) {
                                      return t.$emit("restore-official");
                                    },
                                  },
                                },
                                [e("i", { staticClass: "mdi mdi-restore" })],
                              ),
                            ],
                          )
                        : t._e(),
                      t._t("buttons"),
                    ],
                    2,
                  ),
            ],
            1,
          );
        },
        y = [];
      let v = class extends u.lD {
        constructor(...t) {
          (super(...t),
            (0, h.A)(this, "label", void 0),
            (0, h.A)(this, "personalDictionary", void 0),
            (0, h.A)(this, "matchesRoot", void 0),
            (0, h.A)(this, "hasChanged", void 0),
            (0, h.A)(this, "addOption", void 0),
            (0, h.A)(this, "disabled", void 0));
        }
      };
      ((0, p.Cg)([(0, u.kv)({ default: "" })], v.prototype, "label", void 0),
        (0, p.Cg)(
          [(0, u.kv)({ default: !1 })],
          v.prototype,
          "personalDictionary",
          void 0,
        ),
        (0, p.Cg)(
          [(0, u.kv)({ default: !0 })],
          v.prototype,
          "matchesRoot",
          void 0,
        ),
        (0, p.Cg)(
          [(0, u.kv)({ default: !1 })],
          v.prototype,
          "hasChanged",
          void 0,
        ),
        (0, p.Cg)(
          [(0, u.kv)({ default: null })],
          v.prototype,
          "addOption",
          void 0,
        ),
        (0, p.Cg)(
          [(0, u.kv)({ default: !1 })],
          v.prototype,
          "disabled",
          void 0,
        ),
        (v = (0, p.Cg)([u.uA], v)));
      var b = v,
        w = b,
        D = e(81656),
        _ = (0, D.A)(w, m, y, !1, null, "adf8ed5a", null),
        k = _.exports,
        C = function () {
          var t = this,
            i = t.$createElement,
            e = t._self._c || i;
          return "_" !== t.pair.phoneme
            ? e("div", { staticClass: "is-inline-block phonicsBlock" }, [
                e("div", { staticClass: "phonicsBlockTop" }, [
                  t._v(" " + t._s(t.pair.grapheme) + " "),
                ]),
                e("div", { staticClass: "phonicsBlockMiddle" }, [
                  e("span", [t._v("/" + t._s(t.symbol) + "/")]),
                ]),
                e(
                  "div",
                  {
                    staticClass: "phonicsBlockBottom",
                    on: {
                      click: function (i) {
                        return t.playSoundForPhoneme(t.pair.phoneme, t.locale);
                      },
                    },
                  },
                  [
                    e(
                      "span",
                      { staticClass: "icon" },
                      [
                        e("b-icon", {
                          attrs: { pack: "mdi", icon: "play-circle" },
                        }),
                      ],
                      1,
                    ),
                  ],
                ),
              ])
            : t._e();
        },
        W = [];
      let A = class extends u.lD {
        constructor(...t) {
          (super(...t),
            (0, h.A)(this, "pair", void 0),
            (0, h.A)(this, "symbol", void 0),
            (0, h.A)(this, "locale", void 0),
            (0, h.A)(this, "playSoundForPhoneme", void 0));
        }
      };
      ((0, p.Cg)([(0, u.kv)({ required: !0 })], A.prototype, "pair", void 0),
        (0, p.Cg)([(0, u.kv)({ required: !0 })], A.prototype, "symbol", void 0),
        (0, p.Cg)(
          [(0, u.kv)({ default: "en_GB" })],
          A.prototype,
          "locale",
          void 0,
        ),
        (0, p.Cg)(
          [(0, u.kv)({ required: !0 })],
          A.prototype,
          "playSoundForPhoneme",
          void 0,
        ),
        (A = (0, p.Cg)([u.uA], A)));
      var M = A,
        R = M,
        S = (0, D.A)(R, C, W, !1, null, "4437adc2", null),
        $ = S.exports;
      let x = class extends u.lD {
        constructor(...t) {
          (super(...t),
            (0, h.A)(this, "word", void 0),
            (0, h.A)(this, "wordLocale", void 0),
            (0, h.A)(this, "dictionaryId", void 0),
            (0, h.A)(this, "customIconSize", void 0),
            (0, h.A)(this, "homographs", void 0),
            (0, h.A)(this, "allowCreate", void 0),
            (0, h.A)(this, "phonemesData", void 0),
            (0, h.A)(this, "isEqual", void 0),
            (0, h.A)(this, "playSoundForPhoneme", void 0),
            (0, h.A)(this, "playDictionaryAudio", void 0),
            (0, h.A)(this, "selectedDefinition", null),
            (0, h.A)(this, "dictionaryMoreDetails", null),
            (0, h.A)(this, "symbolForPhoneme", g));
        }
        async mounted() {
          if (0 === this.homographs.length) {
            const t = await f.j.getHomographsOfWord(this.word, this.wordLocale);
            this.homographs.splice(0, 0, ...t.filter((t) => !t.hidden));
          }
          this.dictionaryId
            ? (this.selectedDefinition =
                this.homographs.find((t) => t.id === this.dictionaryId) || null)
            : (this.selectedDefinition =
                this.homographs.find((t) => t.word === this.word) || null);
        }
        get officialHomographs() {
          return this.homographs.filter(
            (t) => 1 === t.user_id && null === t.parent_word,
          );
        }
        get orderedHomographs() {
          const t = [];
          for (const i of this.officialHomographs)
            (t.push(i),
              t.splice(
                t.length,
                0,
                ...this.homographs.filter(
                  (t) => t.parent_word && t.parent_word.id === i.id,
                ),
              ));
          return t;
        }
        get wordNotFoundError() {
          let t = `You entered <strong>"${this.word}"</strong>, but we could not find it in our dictionary. Please check our suggestions below.`;
          return (
            this.allowCreate &&
              (t += ` If the word you are trying to add is not there, and you are sure you have ${this.$t("spelt")} it correctly, we can add it to our dictionary for you.`),
            t
          );
        }
        moreDetailsClicked(t) {
          this.dictionaryMoreDetails =
            this.dictionaryMoreDetails === t ? null : t;
        }
        doesFieldMatchRoot(t, i) {
          return null === t.parent_word || this.isEqual(t[i], t.parent_word[i]);
        }
        submit() {
          var t;
          if (
            (null === (t = this.selectedDefinition) || void 0 === t
              ? void 0
              : t.id) === this.dictionaryId
          )
            return !0;
          this.$emit("selected-dictionary", this.selectedDefinition);
        }
      };
      ((0, p.Cg)([(0, u.kv)({ required: !0 })], x.prototype, "word", void 0),
        (0, p.Cg)(
          [(0, u.kv)({ default: "en_GB" })],
          x.prototype,
          "wordLocale",
          void 0,
        ),
        (0, p.Cg)(
          [(0, u.kv)({ default: null })],
          x.prototype,
          "dictionaryId",
          void 0,
        ),
        (0, p.Cg)(
          [(0, u.kv)({ default: "is-large" })],
          x.prototype,
          "customIconSize",
          void 0,
        ),
        (0, p.Cg)(
          [
            (0, u.kv)({
              default() {
                return [];
              },
            }),
          ],
          x.prototype,
          "homographs",
          void 0,
        ),
        (0, p.Cg)(
          [(0, u.kv)({ default: !1 })],
          x.prototype,
          "allowCreate",
          void 0,
        ),
        (0, p.Cg)(
          [(0, u.kv)({ required: !0 })],
          x.prototype,
          "phonemesData",
          void 0,
        ),
        (0, p.Cg)(
          [(0, u.kv)({ required: !0 })],
          x.prototype,
          "isEqual",
          void 0,
        ),
        (0, p.Cg)(
          [(0, u.kv)({ required: !0 })],
          x.prototype,
          "playSoundForPhoneme",
          void 0,
        ),
        (0, p.Cg)(
          [(0, u.kv)({ required: !0 })],
          x.prototype,
          "playDictionaryAudio",
          void 0,
        ),
        (x = (0, p.Cg)(
          [
            (0, u.uA)({
              components: { PhonicsPairBlock: $, EditDictionaryToolbar: k },
            }),
          ],
          x,
        )));
      var L = x,
        F = L,
        P = (0, D.A)(F, l, c, !1, null, "a5968fca", null),
        O = P.exports,
        H = e(79477),
        E = e(20364),
        U = {
          name: "ListDetail",
          components: {
            StarRating: a.StarRating,
            WordVariantSelector: O,
            ReportListModal: H.A,
          },
          mixins: [E.A],
          props: ["list"],
          data() {
            return {
              listData: null,
              currentPage: 1,
              spellchecker: null,
              showCreateHive: !1,
              changingWord: null,
              addWordHomographOptions: [],
              addWordHomographExact: "",
              addWordHomographAllowCreate: !1,
              changeWordHomographOptions: [],
              showReportList: !1,
              wordData: { items: [], total: 0 },
              tableState: { page: 1, perPage: 10, sort: "text", dir: "asc" },
              loading: !1,
            };
          },
          computed: {
            isOwner() {
              return this.listData.owner === this.$store.state.user.username;
            },
            isEqual() {
              return r.isEqual;
            },
            reportableList() {
              return (
                this.listData.owner !== this.$store.state.user.username &&
                1 !== this.listData.owner_id
              );
            },
          },
          mounted() {
            this.$nextTick(() => {
              (this.loadListData(), this.loadWordData());
            });
          },
          methods: {
            createHive() {
              this.$emit("createhive", this.listData.ident);
            },
            async initDict() {
              if (this.spellchecker) return;
              let t = "en_GB";
              ("en_US" === this.locale && (t = "en_US"),
                await d.D.loadSpellChecker(t),
                (this.spellchecker = {
                  check(t) {
                    return d.D.checkSpelling(t);
                  },
                }));
            },
            async loadFullList() {
              try {
                this.loading = !0;
                const t = await f.j.getListDetailed(this.list, { words: !0 });
                ((this.listData = t),
                  (this.listData.rating = parseFloat(this.listData.rating)));
              } catch (t) {
                this.$buefy.toast.open({
                  duration: 5e3,
                  message: "Could not load list data",
                  type: "is-danger",
                });
              } finally {
                this.loading = !1;
              }
            },
            async loadListData() {
              try {
                this.loading = !0;
                const t = await f.j.getListDetailed(this.list, { words: !1 });
                ((this.listData = t),
                  (this.listData.rating = parseFloat(this.listData.rating)));
              } catch (t) {
                this.$buefy.toast.open({
                  duration: 5e3,
                  message: "Could not load list data",
                  type: "is-danger",
                });
              } finally {
                this.loading = !1;
              }
            },
            async loadWordData() {
              try {
                this.loading = !0;
                const t = await f.j.getWordsForList(
                  this.list,
                  { as_objects: !0 },
                  {
                    take: this.tableState.perPage,
                    skip: (this.tableState.page - 1) * this.tableState.perPage,
                    sort: this.tableState.sort,
                    dir: this.tableState.dir,
                  },
                );
                this.wordData = t;
              } catch (t) {
                this.$buefy.toast.open({
                  duration: 5e3,
                  message: "Could not load words",
                  type: "is-danger",
                });
              } finally {
                this.loading = !1;
              }
            },
            pageChanged(t) {
              ((this.tableState.page = t), this.loadWordData());
            },
            onSort(t) {
              (this.tableState.sort === t
                ? "asc" === this.tableState.dir
                  ? (this.tableState.dir = "desc")
                  : (this.tableState.dir = "asc")
                : ((this.tableState.sort = t), (this.tableState.dir = "asc")),
                this.loadWordData());
            },
            playList() {
              this.listData.list_word_count > 2
                ? this.$emit("play", this.list)
                : this.$buefy.toast.open({
                    duration: 5e3,
                    message: "Not enough words in list",
                    type: "is-danger",
                  });
            },
            unFavourite() {
              n.A.request(
                "delete",
                "lists/" + this.list + "/favourite",
                null,
                this.$store.state.token,
              )
                .then((t) => {
                  const i = t.data;
                  if (i.error)
                    return (console.log(i.error), void alert(i.error));
                  ((this.listData.fav = 0),
                    console.log(this.listData),
                    this.$forceUpdate());
                })
                .catch((t) => {
                  (console.log(t),
                    t.response &&
                      403 === t.response.status &&
                      (console.log("FORBIDDEN"),
                      this.$router.push({ name: "Logout" })),
                    (this.response = "Details incorrect"));
                });
            },
            favourite() {
              n.A.request(
                "put",
                "lists/" + this.list + "/favourite",
                null,
                this.$store.state.token,
              )
                .then((t) => {
                  const i = t.data;
                  if (i.error)
                    return (console.log(i.error), void alert(i.error));
                  (this.$set(this.listData, "fav", 1),
                    console.log(this.listData),
                    this.$forceUpdate());
                })
                .catch((t) => {
                  (console.log(t),
                    t.response &&
                      403 === t.response.status &&
                      (console.log("FORBIDDEN"),
                      this.$router.push({ name: "Logout" })),
                    (this.response = "Details incorrect"));
                });
            },
            sendRating(t) {
              n.A.request(
                "put",
                "lists/" + this.listData.ident + "/rate",
                { rating: t },
                this.$store.state.token,
              )
                .then((t) => {
                  const i = t.data;
                  if (i.error)
                    return (console.log(i.error), void alert(i.error));
                  this.listData.rating = parseFloat(i.list.rating);
                })
                .catch((t) => {
                  (console.log(t),
                    t.response &&
                      403 === t.response.status &&
                      (console.log("FORBIDDEN"),
                      this.$router.push({ name: "Logout" })),
                    (this.response = "Details incorrect"));
                });
            },
            deleteWord(t) {
              console.log(t.dictionary.word);
              const i = window.confirm(
                "Are you sure you want to delete this word?",
              );
              i &&
                n.A.request(
                  "delete",
                  "lists/" + this.listData.ident + "/words/" + t.ident,
                  null,
                  this.$store.state.token,
                )
                  .then((t) => {
                    this.loadListData();
                  })
                  .catch((t) => {
                    (console.log(t),
                      t.response &&
                        403 === t.response.status &&
                        (console.log("FORBIDDEN"),
                        this.$router.push({ name: "Logout" })),
                      (this.response = "Details incorrect"));
                  });
            },
            async changeWordVariant(t) {
              await this.loadFullList();
              const i = await f.j.getHomographsOfWord(
                  t.dictionary.word,
                  this.listData.locale,
                ),
                e = i.filter((t) => !t.parent_word),
                o = this.listData.words.map((t) =>
                  t.dictionary.parent_word
                    ? t.dictionary.parent_word.id
                    : t.dictionary.id,
                ),
                s = e.filter((t) => !o.includes(t.id) && !t.parent_word),
                a = s.concat(
                  t.dictionary.parent_word
                    ? t.dictionary.parent_word
                    : t.dictionary,
                );
              ((this.changeWordHomographOptions = i.filter((t) =>
                a
                  .map((t) => t.id)
                  .includes(t.parent_word ? t.parent_word.id : t.id),
              )),
                (this.changingWord = t));
            },
            async addWord() {
              let t = prompt("Add Word");
              if (t) {
                ((t = t.replace(/‘/g, "'").trim()), await this.initDict());
                const i =
                    (await this.spellchecker.check(t)) &&
                    (t.length > 1 || ["a", "I"].includes(t)),
                  e = this.$store.state.user.school.teacher;
                if (!e && !i)
                  return this.$buefy.toast.open({
                    type: "is-danger",
                    message: `Word "${t}" not found`,
                  });
                const o = (
                  await f.j.getHomographsOfWord(t, this.listData.locale)
                ).filter((t) => !t.hidden);
                if (o.length > 0) {
                  const s = o.filter((t) => !t.parent_word),
                    a = (this.listData.words || []).map((t) =>
                      t.dictionary.parent_word
                        ? t.dictionary.parent_word.id
                        : t.dictionary.id,
                    ),
                    r = s.filter((t) => !a.includes(t.id) && !t.parent_word),
                    n = (this.listData.words || []).find(
                      (i) =>
                        (i.dictionary.parent_word || i.dictionary).word === t,
                    );
                  if (0 === r.length) {
                    if (n)
                      return this.$buefy.toast.open({
                        type: "is-danger",
                        message: "Duplicate Word!",
                      });
                    if (e)
                      this.$buefy.dialog.confirm({
                        title: `Word "${t}" not found`,
                        message: `We couldn't find the word <strong>"${t}"</strong> in our dictionary. If you're sure that it's a valid word and is ${this.$t("spelt")} correctly, we can add it to our dictionary for you.`,
                        confirmText: "Add Word",
                        type: "is-warning",
                        hasIcon: !0,
                        onConfirm: () => this.doAddWord(t),
                      });
                    else {
                      if (!i)
                        return this.$buefy.toast.open({
                          type: "is-danger",
                          message: `Word "${t}" not found`,
                        });
                      this.doAddWord(t);
                    }
                  } else if (1 === r.length)
                    if (t !== r[0].word) {
                      const s = !n && (e || i);
                      ((this.addWordHomographExact = t),
                        (this.addWordHomographAllowCreate = s),
                        (this.addWordHomographOptions = o.filter((t) =>
                          r
                            .map((t) => t.id)
                            .includes(t.parent_word ? t.parent_word.id : t.id),
                        )));
                    } else
                      this.doAddWord({
                        text: r[0].word,
                        dictionary_id: r[0].id,
                      });
                  else {
                    const s = !n && (e || i);
                    ((this.addWordHomographAllowCreate = s),
                      (this.addWordHomographOptions = o.filter((t) =>
                        r
                          .map((t) => t.id)
                          .includes(t.parent_word ? t.parent_word.id : t.id),
                      )),
                      (this.addWordHomographExact = t));
                  }
                } else if (e)
                  this.$buefy.dialog.confirm({
                    title: `Word "${t}" not found`,
                    message: `We couldn't find the word <strong>"${t}"</strong> in our dictionary. If you're sure that it's a valid word and is ${this.$t("spelt")} correctly, we can add it to our dictionary for you.`,
                    confirmText: "Add Word",
                    type: "is-warning",
                    hasIcon: !0,
                    onConfirm: () => this.doAddWord(t),
                  });
                else {
                  if (!i)
                    return this.$buefy.toast.open({
                      type: "is-danger",
                      message: `Word "${t}" not found`,
                    });
                  this.doAddWord(t);
                }
              }
            },
            async doAddWord(t) {
              ((this.listData = await f.j.addWordsToList(this.listData.ident, [
                t,
              ])),
                (this.addWordHomographOptions = []));
            },
            async definitionSelected(t) {
              (await f.j.changeListWordDictionary(
                this.listData.ident,
                this.changingWord.ident,
                t.id,
              ),
                (this.changingWord.dictionary = t),
                (this.changingWord.definitions = JSON.stringify(
                  this.changingWord.dictionary.definitions,
                )),
                (this.changingWord.sentences = JSON.stringify(
                  this.changingWord.dictionary.sentences,
                )),
                (this.changingWord.errors =
                  this.changingWord.dictionary.errors.join(",")),
                (this.changingWord.morphemes =
                  this.changingWord.dictionary.morphemes.join(",")),
                (this.changingWord.phonics =
                  this.changingWord.dictionary.phonics
                    .map((t) => `${t.grapheme}|${t.phoneme}`)
                    .join(",")),
                (this.changingWord = null));
            },
            showReportListModal() {
              this.showReportList = !0;
            },
            hideReportListModal() {
              this.showReportList = !1;
            },
          },
        },
        I = U,
        q = (0, D.A)(I, o, s, !1, null, "23f52521", null),
        B = q.exports;
    },
    42371: function (t, i, e) {
      var o = e(31635),
        s = e(85471),
        a = e(36599);
      const r = {
          maxScore: 2e3,
          thresholds: {
            larve: 200,
            drone: 500,
            worker: 1e3,
            soldier: 1500,
            royal: 1960,
          },
        },
        n = {
          maxScore: 15e3,
          thresholds: {
            larve: 500,
            drone: 1500,
            worker: 2500,
            soldier: 5e3,
            royal: 15e3,
          },
        },
        d = {
          spelling: r,
          number: n,
          quiz: r,
          phonics: r,
          lesson: r,
          grammar: r,
        };
      let l = class extends s["default"] {
        badgeImage(t, i) {
          const e = d[t];
          return i >= e.thresholds.royal
            ? "badgeRoyal.png"
            : i >= e.thresholds.soldier
              ? "badgeSoldier.png"
              : i >= e.thresholds.worker
                ? "badgeWorker.png"
                : i >= e.thresholds.drone
                  ? "badgeDrone.png"
                  : i >= e.thresholds.larve
                    ? "badgeLarve.png"
                    : "badgeEgg.png";
        }
        badgeProgress(t, i) {
          const e = d[t];
          return i >= e.thresholds.royal
            ? 100
            : i >= e.thresholds.soldier
              ? (100 * (i - e.thresholds.soldier)) /
                (e.thresholds.royal - e.thresholds.soldier)
              : i >= e.thresholds.worker
                ? (100 * (i - e.thresholds.worker)) /
                  (e.thresholds.soldier - e.thresholds.worker)
                : i >= e.thresholds.drone
                  ? (100 * (i - e.thresholds.drone)) /
                    (e.thresholds.worker - e.thresholds.drone)
                  : i >= e.thresholds.larve
                    ? (100 * (i - e.thresholds.larve)) /
                      (e.thresholds.drone - e.thresholds.larve)
                    : (100 * i) / e.thresholds.larve;
        }
        badgePointsNeeded(t, i) {
          const e = d[t];
          return i >= e.thresholds.royal
            ? null
            : i >= e.thresholds.soldier
              ? e.thresholds.royal - i
              : i >= e.thresholds.worker
                ? e.thresholds.soldier - i
                : i >= e.thresholds.drone
                  ? e.thresholds.worker - i
                  : i >= e.thresholds.larve
                    ? e.thresholds.drone - i
                    : e.thresholds.larve - i;
        }
        nextScore(t, i) {
          const e = d[t];
          return i >= e.thresholds.royal
            ? e.maxScore
            : i >= e.thresholds.soldier
              ? e.thresholds.royal
              : i >= e.thresholds.worker
                ? e.thresholds.soldier
                : i >= e.thresholds.drone
                  ? e.thresholds.worker
                  : i >= e.thresholds.larve
                    ? e.thresholds.drone
                    : e.thresholds.larve;
        }
        badgeTitle(t, i) {
          const e = d[t];
          return i >= e.thresholds.royal
            ? "Royal Bee"
            : i >= e.thresholds.soldier
              ? "Soldier Bee"
              : i >= e.thresholds.worker
                ? "Worker Bee"
                : i >= e.thresholds.drone
                  ? "Drone"
                  : i >= e.thresholds.larve
                    ? "Larva"
                    : "Egg";
        }
      };
      ((l = (0, o.Cg)([(0, a.Ay)({ name: "BadgeHelper" })], l)), (i.A = l));
    },
    79477: function (t, i, e) {
      e.d(i, {
        A: function () {
          return y;
        },
      });
      var o = function () {
          var t = this,
            i = t.$createElement,
            e = t._self._c || i;
          return e("div", { staticClass: "modal is-active is-large" }, [
            e("div", {
              staticClass: "modal-background",
              on: {
                click: function (i) {
                  return (i.preventDefault(), t.$emit("close"));
                },
              },
            }),
            e("div", { staticClass: "modal-card" }, [
              e("header", { staticClass: "modal-card-head" }, [
                e("p", { staticClass: "modal-card-title" }, [
                  t._v(" Report Spelling List "),
                ]),
                e("button", {
                  staticClass: "delete",
                  attrs: { "aria-label": "close" },
                  on: {
                    click: function (i) {
                      return t.closeView();
                    },
                  },
                }),
              ]),
              e("section", { staticClass: "modal-card-body" }, [
                e(
                  "div",
                  { staticClass: "content" },
                  [
                    t.isPupil
                      ? e("div", { staticClass: "notification is-danger" }, [
                          e("p", [
                            t._v(
                              "REPORT INAPPROPRIATE WORDS OR BULLYING TO YOUR TEACHER",
                            ),
                          ]),
                        ])
                      : t._e(),
                    e(
                      "b-field",
                      { attrs: { label: "Reason" } },
                      [
                        e(
                          "b-select",
                          {
                            attrs: { placeholder: "Select a reason" },
                            model: {
                              value: t.reason,
                              callback: function (i) {
                                t.reason = i;
                              },
                              expression: "reason",
                            },
                          },
                          t._l(t.ReportListType, function (i) {
                            return e(
                              "option",
                              { key: i, domProps: { value: i } },
                              [t._v(" " + t._s(i) + " ")],
                            );
                          }),
                          0,
                        ),
                      ],
                      1,
                    ),
                    e(
                      "b-field",
                      { attrs: { label: "Description" } },
                      [
                        e("b-input", {
                          attrs: { maxlength: "250", type: "textarea" },
                          model: {
                            value: t.description,
                            callback: function (i) {
                              t.description = i;
                            },
                            expression: "description",
                          },
                        }),
                      ],
                      1,
                    ),
                  ],
                  1,
                ),
              ]),
              e("footer", { staticClass: "modal-card-foot" }, [
                e(
                  "button",
                  {
                    staticClass: "button is-success",
                    attrs: { disabled: !t.canSubmit },
                    on: { click: t.sendReport },
                  },
                  [t._v(" Submit ")],
                ),
              ]),
            ]),
          ]);
        },
        s = [],
        a = e(91114),
        r = (e(89463), e(16280), e(42762), e(62953), e(31635)),
        n = e(18657),
        d = e(53235),
        l = e(43564);
      const c = ["Inappropriate", "Bullying", "Other"],
        h = [
          "Inappropriate",
          "Spelling mistake",
          "Incorrect dictionary data",
          "Other",
        ];
      let p = class extends (0, n.Xe)(d.A) {
        constructor(...t) {
          (super(...t),
            (0, a.A)(this, "id", void 0),
            (0, a.A)(this, "description", ""),
            (0, a.A)(this, "reason", null),
            (0, a.A)(this, "ReportListType", []));
        }
        closeView() {
          this.$emit("close");
        }
        mounted() {
          this.ReportListType = this.isPupil ? c : h;
        }
        get canSubmit() {
          return (
            0 !== this.description.trim().length && !!this.reason && !!this.id
          );
        }
        get isPupil() {
          return 1 !== this.$store.state.user.school.teacher;
        }
        async sendReport() {
          try {
            if (!this.reason)
              return this.$buefy.toast.open({
                message: "Please select a reason",
                position: "is-bottom",
                type: "is-danger",
              });
            if (0 === this.description.trim().length)
              return this.$buefy.toast.open({
                message: "Please enter a description",
                position: "is-bottom",
                type: "is-danger",
              });
            (await l.j.reportList(this.id, {
              description: this.description,
              type: this.reason,
            }),
              this.$buefy.toast.open({
                message: "Report submitted. Thank you for your feedback.",
                position: "is-bottom",
                type: "is-success",
              }),
              this.closeView());
          } catch (t) {
            if (t instanceof Error)
              return this.$buefy.toast.open({
                message: t.message,
                position: "is-bottom",
                type: "is-danger",
              });
          }
        }
      };
      ((0, r.Cg)([(0, n.kv)({ required: !0 })], p.prototype, "id", void 0),
        (p = (0, r.Cg)([(0, n.uA)({ name: "ReportListModal" })], p)));
      var u = p,
        g = u,
        f = e(81656),
        m = (0, f.A)(g, o, s, !1, null, "0eae8cfb", null),
        y = m.exports;
    },
  },
]);
//# sourceMappingURL=752.1778511f.js.map
