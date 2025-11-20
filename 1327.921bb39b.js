"use strict";
(self["webpackChunkgame"] = self["webpackChunkgame"] || []).push([
  [1327],
  {
    20364: function (t, e, s) {
      var a = s(91114),
        i =
          (s(16280),
          s(44114),
          s(18111),
          s(22489),
          s(20116),
          s(27495),
          s(25440),
          s(62953),
          s(31635)),
        r = s(18657),
        n = s(94196),
        o = s(7504),
        l = s(13865);
      let c = class extends r.lD {
        constructor(...t) {
          (super(...t),
            (0, a.A)(this, "soundBank", []),
            (0, a.A)(
              this,
              "userLocale",
              (0, l.wl)(this.$i18n.locale).underscored,
            ));
        }
        speakDictionary(t, e) {
          var s, a, i, r, n, o;
          if (
            (null !== (s = t.audio_versions) &&
              void 0 !== s &&
              s[this.userLocale]) ||
            (null !== (a = t.parent_word) &&
              void 0 !== a &&
              null !== (i = a.audio_versions) &&
              void 0 !== i &&
              i[this.userLocale]) ||
            (null !== (r = t.audio_versions) && void 0 !== r && r[t.locale]) ||
            (null !== (n = t.parent_word) &&
              void 0 !== n &&
              null !== (o = n.audio_versions) &&
              void 0 !== o &&
              o[t.locale]) ||
            t.variant_audio
          )
            return this.playCustomAudio(t);
          this.speak(t.word, !1, e || t.locale);
        }
        playSoundForPhoneme(t, e) {
          if (!t) return;
          ("en_NZ" === e.underscored && (e.underscored = "en_AU"),
            "en_IE" === e.underscored && (e.underscored = "en_GB"));
          const s =
              "https://files.edshed.com/audio/dictionary/" +
              e +
              "/PHONICS/mp3/" +
              t.toLowerCase() +
              ".mp3",
            a =
              "https://files.edshed.com/audio/dictionary/" +
              e +
              "/PHONICS/ogg/" +
              t.toLowerCase() +
              ".ogg",
            i = new n.Howl({
              src: a,
              autoplay: !1,
              html5: o.A.useHtml5Audio,
              onloaderror: () => {
                const a = new n.Howl({
                  src: s,
                  autoplay: !1,
                  html5: o.A.useHtml5Audio,
                  onloaderror: () => {
                    this.speakTTS(t, e.underscored);
                  },
                  onload: () => {
                    (a.play(), this.stopSounds(), this.soundBank.push(a));
                  },
                });
              },
              onload: () => {
                (this.stopSounds(), this.soundBank.push(i), i.play());
              },
            });
        }
        speak(t, e, s) {
          if (t) {
            let a = s;
            if (this.$store.state.user) {
              const t = (0, l.lh)(this.$store.state.user.locale),
                e = (0, l.lh)(s);
              t.language === e.language &&
                t.country !== e.country &&
                (a = t.underscored);
            }
            const i = e
                ? this.getPhonemeAudioFile(a, t)
                : this.getDictionaryWordAudioFile(a, t),
              r = new n.Howl({
                src: i.ogg,
                autoplay: !1,
                html5: o.A.useHtml5Audio,
                onloaderror: () => {
                  const e = new n.Howl({
                    src: i.mp3,
                    autoplay: !1,
                    html5: o.A.useHtml5Audio,
                    onloaderror: () => {
                      this.speakTTS(t, a);
                    },
                    onload: () => {
                      (e.play(), this.stopSounds(), this.soundBank.push(e));
                    },
                  });
                },
                onload: () => {
                  (this.stopSounds(), this.soundBank.push(r), r.play());
                },
              });
          }
        }
        playAudio(t) {
          try {
            const e = t.filePath,
              s = t.filePath ? t.filePath.slice(0, -3) + "ogg" : void 0;
            if (!e || !s) throw new Error("No audio");
            const a = new n.Howl({
              src: [e, s],
              html5: o.A.useHtml5Audio,
              onloaderror: () => {
                throw new Error("Cannot load audio");
              },
            });
            (this.stopSounds(), a.play(), this.soundBank.push(a));
          } catch (e) {
            let t = "Could not play the audio";
            (e instanceof Error && (t = e.message),
              this.$buefy.toast.open({
                message: t,
                position: "is-bottom",
                type: "is-danger",
              }));
          }
        }
        playCustomAudio(t) {
          var e, s;
          let a;
          var i, r;
          null !== (e = this.$store.state.user) &&
            void 0 !== e &&
            null !== (s = e.school) &&
            void 0 !== s &&
            s.settings &&
            (a =
              null === (i = this.$store.state.user) ||
              void 0 === i ||
              null === (r = i.school) ||
              void 0 === r
                ? void 0
                : r.settings.trap_bath);
          const {
            variant_type: n,
            variant_audio: o,
            audio_versions: l,
            word: c,
            locale: u,
          } = t;
          if (a && "Trap-bath" === n && o)
            try {
              return void this.playAudio(o);
            } catch (d) {}
          if (null !== l && void 0 !== l && l[this.userLocale])
            try {
              return void this.playAudio(
                null === l || void 0 === l ? void 0 : l[this.userLocale],
              );
            } catch (p) {}
          if (null !== l && void 0 !== l && l[u])
            try {
              return void this.playAudio(
                null === l || void 0 === l ? void 0 : l[u],
              );
            } catch (h) {}
          this.speak(c, !1, u);
        }
        speakTTS(t, e) {
          const s = this.getTTSpeechAudioFile(e, t),
            a = new n.Howl({
              src: s.ogg,
              autoplay: !1,
              html5: o.A.useHtml5Audio,
              onloaderror: () => {
                const a = new n.Howl({
                  src: s.mp3,
                  autoplay: !1,
                  html5: o.A.useHtml5Audio,
                  onloaderror: () => {
                    this.speakBrowserSynthesis(t, e);
                  },
                  onload: () => {
                    (a.play(), this.stopSounds(), this.soundBank.push(a));
                  },
                });
              },
              onload: () => {
                (this.stopSounds(), this.soundBank.push(a), a.play());
              },
            });
        }
        speakBrowserSynthesis(t, e) {
          if (!SpeechSynthesisUtterance)
            throw new Error(
              "SpeechSynthesisUtterance not supported on your browser",
            );
          {
            const s = new SpeechSynthesisUtterance(t),
              a = window.speechSynthesis.getVoices();
            for (let t = 0; t < a.length; t++)
              if (a[t].lang === e || a[t].lang === e.replace("_", "-")) {
                s.voice = a[t];
                break;
              }
            (window.speechSynthesis.cancel(), window.speechSynthesis.speak(s));
          }
        }
        checkSoundBank() {
          (this.soundBank || (this.soundBank = []),
            (this.soundBank = this.soundBank.filter((t) => t.playing())));
        }
        stopSounds() {
          this.checkSoundBank();
          for (const t of this.soundBank) t.stop();
        }
        getTTSpeechAudioFile(t, e) {
          const s = `${o.A.serverURI}audio/${t}/${encodeURIComponent(e.toLocaleLowerCase())}`;
          return { mp3: `${s}.mp3`, ogg: `${s}.ogg` };
        }
        getDictionaryWordAudioFile(t, e) {
          const s = "https://files.edshed.com/audio/dictionary/";
          const a = encodeURIComponent(e),
            i = encodeURIComponent(e)[0].toUpperCase(),
            r = `${s}${t}/${i}/mp3/${a.toLocaleLowerCase()}.mp3`,
            n = `${s}${t}/${i}/ogg/${a.toLocaleLowerCase()}.ogg`;
          return { mp3: r, ogg: n };
        }
        getPhonemeAudioFile(t, e) {
          const s = "https://files.edshed.com/audio/dictionary/";
          let a = e.toLowerCase();
          "c" === a && (a = "k");
          const i = `${s}${t}/PHONICS/mp3/${a}.mp3`,
            r = `${s}${t}/PHONICS/ogg/${a}.ogg`;
          return { mp3: i, ogg: r };
        }
        stopHowler() {
          (console.log(n.Howler), n.Howler.stop());
        }
        howlerHasAudioPlaying() {
          return !!n.Howler._howls.find((t) => t.playing());
        }
      };
      ((c = (0, i.Cg)([r.uA], c)), (e.A = c));
    },
    24580: function (t, e, s) {
      s.d(e, {
        A: function () {
          return g;
        },
      });
      var a = function () {
          var t = this,
            e = t.$createElement,
            s = t._self._c || e;
          return s(
            "svg",
            {
              staticClass: "badge",
              attrs: { height: t.height, width: t.width },
            },
            [
              s("image", {
                class: t.animating
                  ? "badge-element"
                  : "badge-element notransition",
                attrs: {
                  preserveAspectRatio: "none",
                  href: t.currentImage,
                  x: (-11 / 135) * t.imageWidth + t.stroke + 2,
                  y: (-9 / 153) * t.imageHeight + t.stroke + 2,
                  height: t.imageHeight,
                  width: t.imageWidth,
                },
              }),
              s("image", {
                class: t.animating
                  ? "badge-element"
                  : "badge-element notransition",
                attrs: {
                  opacity: t.transitioning ? 0 : 1,
                  preserveAspectRatio: "none",
                  href: t.transitionImage,
                  x: (-11 / 135) * t.imageWidth + t.stroke + 2,
                  y: (-9 / 153) * t.imageHeight + t.stroke + 2,
                  height: t.imageHeight,
                  width: t.imageWidth,
                },
              }),
              s("polygon", {
                class: t.animating ? "" : "notransition",
                attrs: {
                  points: t.points,
                  stroke: "white",
                  "stroke-width": t.stroke,
                  fill: "transparent",
                },
              }),
              s("polygon", {
                class: t.animating ? "" : "notransition",
                style: { strokeDashoffset: t.strokeDashoffset },
                attrs: {
                  points: t.points,
                  stroke: "white",
                  "stroke-dasharray": t.perimeter,
                  "stroke-width": t.stroke + 2,
                  fill: "transparent",
                },
              }),
              s("polygon", {
                class: t.animating ? "" : "notransition",
                style: { strokeDashoffset: t.strokeDashoffset },
                attrs: {
                  points: t.points,
                  stroke: "#e9ce1d",
                  "stroke-dasharray": t.perimeter,
                  "stroke-width": t.stroke,
                  fill: "transparent",
                },
              }),
              s("polygon", {
                class: t.animating ? "" : "notransition",
                style: { strokeDashoffset: t.strokeDashoffset },
                attrs: {
                  points: t.points,
                  stroke: "gray",
                  "stroke-linecap": "round",
                  "stroke-dasharray": "0, " + t.perimeter,
                  "stroke-width": 2 * t.stroke + 2,
                  fill: "transparent",
                },
              }),
              s("polygon", {
                class: t.animating ? "" : "notransition",
                style: { strokeDashoffset: t.strokeDashoffset },
                attrs: {
                  points: t.points,
                  stroke: "white",
                  "stroke-linecap": "round",
                  "stroke-dasharray": "0, " + t.perimeter,
                  "stroke-width": 2 * t.stroke,
                  fill: "transparent",
                },
              }),
            ],
          );
        },
        i = [],
        r = s(91114),
        n = (s(62953), s(31635)),
        o = s(85471),
        l = s(18657);
      let c = class extends o["default"] {
        constructor(...t) {
          (super(...t),
            (0, r.A)(this, "radius", void 0),
            (0, r.A)(this, "progress", void 0),
            (0, r.A)(this, "image", void 0),
            (0, r.A)(this, "animating", void 0),
            (0, r.A)(this, "transitionImage", ""),
            (0, r.A)(this, "transitioning", !1));
        }
        onProgressChanged(t, e) {
          const s = this,
            a = this.animating;
          (console.log(a),
            o["default"].nextTick(function () {
              (s.$emit("progress-updated"),
                console.log("progress is " + t),
                a &&
                  setTimeout(() => {
                    s.$emit("progress-transition-complete");
                  }, 1e3));
            }));
        }
        onImageChanged(t, e) {
          const s = this;
          o["default"].nextTick(function () {
            ((s.transitionImage = "" === e ? t : e),
              (s.transitioning = !0),
              o["default"].nextTick(function () {
                setTimeout(() => {
                  ((s.transitionImage = t),
                    (s.transitioning = !1),
                    s.$emit("badge-transition-complete"));
                }, 1e3);
              }));
          });
        }
        get currentProgress() {
          return this.progress;
        }
        get currentImage() {
          return this.image;
        }
        get currentRadius() {
          return this.radius;
        }
        get stroke() {
          return (6 * this.currentRadius) / 50;
        }
        get perimeter() {
          return 6 * this.currentRadius;
        }
        get strokeDashoffset() {
          return this.perimeter - (this.currentProgress / 100) * this.perimeter;
        }
        get height() {
          return (153 * (2 * this.currentRadius + 2 * this.stroke)) / 129;
        }
        get width() {
          return (
            (135 *
              (2 * Math.sin(Math.PI / 3) * this.currentRadius +
                2 * this.stroke)) /
            113
          );
        }
        get imageHeight() {
          return (
            (153 * (2 * this.currentRadius + 2 * this.stroke)) / 123 -
            2.5 * this.stroke
          );
        }
        get imageWidth() {
          return (
            (135 *
              (2 * Math.sin(Math.PI / 3) * this.currentRadius +
                2 * this.stroke)) /
              107 -
            2.5 * this.stroke
          );
        }
        get points() {
          const t = [
              this.currentRadius * Math.sin(Math.PI / 3) + this.stroke + 2,
              this.stroke + 2,
            ].join(","),
            e = [
              2 * this.currentRadius * Math.sin(Math.PI / 3) + this.stroke + 2,
              0.5 * this.currentRadius + this.stroke + 2,
            ].join(","),
            s = [
              2 * this.currentRadius * Math.sin(Math.PI / 3) + this.stroke + 2,
              1.5 * this.currentRadius + this.stroke + 2,
            ].join(","),
            a = [
              this.currentRadius * Math.sin(Math.PI / 3) + this.stroke + 2,
              2 * this.currentRadius + this.stroke + 2,
            ].join(","),
            i = [
              this.stroke + 2,
              1.5 * this.currentRadius + this.stroke + 2,
            ].join(","),
            r = [
              this.stroke + 2,
              0.5 * this.currentRadius + this.stroke + 2,
            ].join(","),
            n = [t, e, s, a, i, r];
          return n.join(" ");
        }
      };
      ((0, n.Cg)(
        [(0, l.kv)({ type: Number, default: 50 })],
        c.prototype,
        "radius",
        void 0,
      ),
        (0, n.Cg)(
          [(0, l.kv)({ type: Number, default: 0 })],
          c.prototype,
          "progress",
          void 0,
        ),
        (0, n.Cg)(
          [(0, l.kv)({ type: String, default: "/images/badgeEgg.png" })],
          c.prototype,
          "image",
          void 0,
        ),
        (0, n.Cg)(
          [(0, l.kv)({ type: Boolean, default: !0 })],
          c.prototype,
          "animating",
          void 0,
        ),
        (0, n.Cg)(
          [(0, l.ox)("progress")],
          c.prototype,
          "onProgressChanged",
          null,
        ),
        (0, n.Cg)([(0, l.ox)("image")], c.prototype, "onImageChanged", null),
        (c = (0, n.Cg)([l.uA], c)));
      var u = c,
        d = u,
        p = s(81656),
        h = (0, p.A)(d, a, i, !1, null, "0ae0b1d6", null),
        g = h.exports;
    },
    46750: function (t, e, s) {
      s.d(e, {
        A: function () {
          return u;
        },
      });
      var a = function () {
          var t = this,
            e = t.$createElement,
            s = t._self._c || e;
          return s("figure", [
            s(
              "a",
              {
                staticClass: "menu-button",
                attrs: { href: "#" },
                on: {
                  click: function (e) {
                    return (e.preventDefault(), t.tappedButton(e));
                  },
                },
              },
              [
                s("img", {
                  staticClass: "menu-button__img",
                  attrs: { src: "/images/menuButton.png" },
                }),
                s("div", { staticClass: "menu-button__content" }, [
                  t.hasBadge
                    ? s("img", {
                        staticClass: "menu-button__badge",
                        attrs: {
                          src: "/images/" + t.theBadgeImage,
                          title: t.theBadgeTitle,
                        },
                      })
                    : t._e(),
                  s("div", { staticClass: "menu-button__content__title" }, [
                    s(
                      "p",
                      {
                        staticClass: "menu-button__title",
                        class: {
                          hasSubtitle: t.hasSubtitle,
                          hasBadge: t.hasBadge,
                        },
                      },
                      [s("span", [t._v(t._s(t.title))])],
                    ),
                    t.hasSubtitle
                      ? s("p", { staticClass: "menu-button__subtitle" }, [
                          s("span", [t._v(t._s(t.subtitle))]),
                        ])
                      : t._e(),
                  ]),
                ]),
              ],
            ),
          ]);
        },
        i = [],
        r = s(42371),
        n = {
          name: "MenuButton",
          mixins: [r.A],
          props: ["title", "subtitle", "index", "statusScore"],
          computed: {
            hasSubtitle() {
              return this.subtitle && "" !== this.subtitle;
            },
            hasBadge() {
              return null != this.statusScore;
            },
            theBadgeImage() {
              return this.badgeImage("spelling", this.statusScore);
            },
            theBadgeTitle() {
              return this.badgeTitle("spelling", this.statusScore);
            },
          },
          methods: {
            tappedButton() {
              this.$emit("didClick", this.index);
            },
          },
        },
        o = n,
        l = s(81656),
        c = (0, l.A)(o, a, i, !1, null, "12fcc930", null),
        u = c.exports;
    },
    80424: function (t, e, s) {
      s.d(e, {
        A: function () {
          return y;
        },
      });
      var a = function () {
          var t = this,
            e = t.$createElement,
            s = t._self._c || e;
          return s(
            "div",
            { staticClass: "modal is-active", attrs: { id: "listsModal" } },
            [
              s("div", {
                staticClass: "modal-background",
                on: {
                  click: function (e) {
                    return (e.preventDefault(), t.hideLists(e));
                  },
                },
              }),
              s("div", { staticClass: "modal-content" }, [
                s("div", { staticClass: "box" }, [
                  t.showListDetail
                    ? t._e()
                    : s("div", { staticClass: "is-pulled-right" }, [
                        s(
                          "button",
                          {
                            class: t.isReloadingUser
                              ? "button is-white is-loading"
                              : "button is-white",
                            on: { click: t.reloadUser },
                          },
                          [s("i", { staticClass: "mdi mdi-reload" })],
                        ),
                      ]),
                  t.limitLists || t.listDetail
                    ? t._e()
                    : s("div", { staticClass: "tabs is-toggle is-centered" }, [
                        s("ul", [
                          t.homework
                            ? s(
                                "li",
                                {
                                  class: { "is-active": 0 == t.tabIndex },
                                  attrs: { id: "tab-assignments" },
                                },
                                [
                                  s(
                                    "a",
                                    {
                                      on: {
                                        click: function (e) {
                                          return (
                                            e.preventDefault(),
                                            t.didTapAssignments(e)
                                          );
                                        },
                                      },
                                    },
                                    [t._m(0), s("span", [t._v("Assignments")])],
                                  ),
                                ],
                              )
                            : t._e(),
                          s(
                            "li",
                            {
                              class: { "is-active": 1 == t.tabIndex },
                              attrs: { id: "tab-my-lists" },
                            },
                            [
                              s(
                                "a",
                                {
                                  on: {
                                    click: function (e) {
                                      return (
                                        e.preventDefault(),
                                        t.didTapMyLists(e)
                                      );
                                    },
                                  },
                                },
                                [t._m(1), s("span", [t._v("My Lists")])],
                              ),
                            ],
                          ),
                          s(
                            "li",
                            {
                              class: { "is-active": 4 == t.tabIndex },
                              attrs: { id: "tab-my-lists" },
                            },
                            [
                              s(
                                "a",
                                {
                                  on: {
                                    click: function (e) {
                                      return (
                                        e.preventDefault(),
                                        t.didTapSchemeLists(e)
                                      );
                                    },
                                  },
                                },
                                [
                                  t._m(2),
                                  "en_US" == t.$store.state.user.locale
                                    ? s("span", [t._v("Curriculum")])
                                    : s("span", [t._v("Scheme")]),
                                ],
                              ),
                            ],
                          ),
                          s(
                            "li",
                            {
                              class: { "is-active": 3 == t.tabIndex },
                              attrs: { id: "tab-pastassignments" },
                            },
                            [
                              s(
                                "a",
                                {
                                  on: {
                                    click: function (e) {
                                      return (
                                        e.preventDefault(),
                                        t.didTapPastAssignments(e)
                                      );
                                    },
                                  },
                                },
                                [
                                  t._m(3),
                                  t.$store.state.user.school.teacher
                                    ? s("span", [t._v("Assignments")])
                                    : s("span", [t._v("Past Assignments")]),
                                ],
                              ),
                            ],
                          ),
                          s(
                            "li",
                            {
                              class: { "is-active": 2 == t.tabIndex },
                              attrs: { id: "tab-search" },
                            },
                            [
                              s(
                                "a",
                                {
                                  on: {
                                    click: function (e) {
                                      return (
                                        e.preventDefault(),
                                        t.didTapSearch(e)
                                      );
                                    },
                                  },
                                },
                                [t._m(4), s("span", [t._v("Search")])],
                              ),
                            ],
                          ),
                        ]),
                      ]),
                  5 === t.tabIndex
                    ? s("div", [
                        s("h2", [t._v("SPAG Quizzes")]),
                        s("div", { staticClass: "spag-list" }),
                      ])
                    : t._e(),
                  t.homework && 0 == t.tabIndex && !t.listDetail
                    ? s(
                        "div",
                        [
                          s("h2", [t._v("Assignments")]),
                          s(
                            "b-table",
                            {
                              attrs: {
                                data: t.homework,
                                paginated: !0,
                                "current-page": t.currentPage,
                                "pagination-simple": !1,
                                "per-page": 10,
                                "mobile-cards": !0,
                                striped: !0,
                                sort: !1,
                              },
                              on: {
                                "update:data": function (e) {
                                  t.homework = e;
                                },
                                "update:currentPage": function (e) {
                                  t.currentPage = e;
                                },
                                "update:current-page": function (e) {
                                  t.currentPage = e;
                                },
                              },
                            },
                            [
                              s("b-table-column", {
                                attrs: { field: "title", label: "Task" },
                                scopedSlots: t._u(
                                  [
                                    {
                                      key: "default",
                                      fn: function (e) {
                                        return [
                                          s("p", [
                                            s("b", [t._v(t._s(e.row.title))]),
                                          ]),
                                          "diagnostic" !== e.row.subtype
                                            ? s("p", [
                                                s("small", [
                                                  s("i", [
                                                    t._v(t._s(e.row.list_name)),
                                                  ]),
                                                ]),
                                              ])
                                            : t._e(),
                                          s("p", [
                                            s("small", [
                                              e.row.hide_other_lists
                                                ? s("span", [t._v("🔴")])
                                                : e.row.number_plays &&
                                                    e.row.games_played >=
                                                      e.row.number_plays
                                                  ? s("span", [t._v("✅")])
                                                  : t._e(),
                                              t._v(
                                                " " +
                                                  t._s(
                                                    t.subTitleForButton(
                                                      e.index +
                                                        10 *
                                                          (t.currentPage - 1),
                                                    ),
                                                  ) +
                                                  " ",
                                              ),
                                            ]),
                                          ]),
                                        ];
                                      },
                                    },
                                  ],
                                  null,
                                  !1,
                                  2538372148,
                                ),
                              }),
                              s("b-table-column", {
                                attrs: {
                                  field: "status_score_max",
                                  width: "200px",
                                },
                                scopedSlots: t._u(
                                  [
                                    {
                                      key: "default",
                                      fn: function (e) {
                                        return [
                                          s("img", {
                                            staticStyle: {
                                              "vertical-align": "middle",
                                              "max-height": "50px",
                                              float: "left",
                                            },
                                            attrs: {
                                              src:
                                                "/images/" +
                                                t.badgeImage(
                                                  "spelling",
                                                  e.row.status_score_max,
                                                ),
                                              title: t.badgeTitle(
                                                "spelling",
                                                e.row.status_score_max,
                                              ),
                                            },
                                          }),
                                          s("p", [
                                            t._v(
                                              t._s(
                                                t.badgeTitle(
                                                  "spelling",
                                                  e.row.status_score_max,
                                                ),
                                              ),
                                            ),
                                          ]),
                                          s("p", [
                                            s("small", [
                                              s("i", [
                                                t._v(
                                                  t._s(e.row.status_score_max) +
                                                    " / " +
                                                    t._s(
                                                      t.nextScore(
                                                        "spelling",
                                                        e.row.status_score_max,
                                                      ),
                                                    ),
                                                ),
                                              ]),
                                            ]),
                                          ]),
                                        ];
                                      },
                                    },
                                  ],
                                  null,
                                  !1,
                                  1628832042,
                                ),
                              }),
                              s("b-table-column", {
                                attrs: { label: "" },
                                scopedSlots: t._u(
                                  [
                                    {
                                      key: "default",
                                      fn: function (e) {
                                        return [
                                          "spelling" === e.row.type &&
                                          "diagnostic" === e.row.subtype
                                            ? s(
                                                "a",
                                                {
                                                  staticClass:
                                                    "button is-primary is-pulled-right",
                                                  attrs: { href: "#" },
                                                  on: {
                                                    click: function (s) {
                                                      return (
                                                        s.preventDefault(),
                                                        t.playDiagnosticListFromAssignment(
                                                          e.row,
                                                        )
                                                      );
                                                    },
                                                  },
                                                },
                                                [t._v("Play")],
                                              )
                                            : "spelling" === e.row.type
                                              ? s(
                                                  "a",
                                                  {
                                                    staticClass:
                                                      "button is-primary is-pulled-right",
                                                    attrs: { href: "#" },
                                                    on: {
                                                      click: function (s) {
                                                        return (
                                                          s.preventDefault(),
                                                          t.showListDetailFromAssignment(
                                                            e.row,
                                                          )
                                                        );
                                                      },
                                                    },
                                                  },
                                                  [t._v("Details")],
                                                )
                                              : "quiz" === e.row.type
                                                ? s(
                                                    "a",
                                                    {
                                                      staticClass:
                                                        "button is-success is-pulled-right",
                                                      attrs: { href: "#" },
                                                      on: {
                                                        click: function (s) {
                                                          return (
                                                            s.preventDefault(),
                                                            t.startQuizFromAssignment(
                                                              e.row,
                                                            )
                                                          );
                                                        },
                                                      },
                                                    },
                                                    [t._v("Play")],
                                                  )
                                                : "lesson" === e.row.type
                                                  ? s(
                                                      "a",
                                                      {
                                                        staticClass:
                                                          "button is-success is-pulled-right",
                                                        attrs: { href: "#" },
                                                        on: {
                                                          click: function (s) {
                                                            return (
                                                              s.preventDefault(),
                                                              t.showLessonFromAssignment(
                                                                e.row,
                                                              )
                                                            );
                                                          },
                                                        },
                                                      },
                                                      [t._v("Play")],
                                                    )
                                                  : t._e(),
                                        ];
                                      },
                                    },
                                  ],
                                  null,
                                  !1,
                                  4263232145,
                                ),
                              }),
                            ],
                            1,
                          ),
                        ],
                        1,
                      )
                    : t._e(),
                  1 != t.tabIndex || t.listDetail
                    ? t._e()
                    : s("div", { attrs: { id: "myLists" } }, [
                        t.suggested && !t.limitLists
                          ? s(
                              "div",
                              [
                                s("h2", [t._v("Suggested")]),
                                s(
                                  "b-table",
                                  {
                                    attrs: {
                                      data: t.suggested,
                                      paginated: !1,
                                      "per-page": 6,
                                      "mobile-cards": !0,
                                      striped: !0,
                                      sort: !1,
                                    },
                                    on: {
                                      "update:data": function (e) {
                                        t.suggested = e;
                                      },
                                    },
                                  },
                                  [
                                    s("b-table-column", {
                                      attrs: { field: "title", label: "List" },
                                      scopedSlots: t._u(
                                        [
                                          {
                                            key: "default",
                                            fn: function (e) {
                                              return [
                                                s("p", [
                                                  s("b", [
                                                    t._v(t._s(e.row.title)),
                                                  ]),
                                                ]),
                                              ];
                                            },
                                          },
                                        ],
                                        null,
                                        !1,
                                        4289380271,
                                      ),
                                    }),
                                    s("b-table-column", {
                                      attrs: { label: "" },
                                      scopedSlots: t._u(
                                        [
                                          {
                                            key: "default",
                                            fn: function (e) {
                                              return [
                                                s(
                                                  "a",
                                                  {
                                                    staticClass:
                                                      "button is-primary is-pulled-right",
                                                    attrs: { href: "#" },
                                                    on: {
                                                      click: function (s) {
                                                        return (
                                                          s.preventDefault(),
                                                          t.showListDetail(
                                                            e.row.ident,
                                                          )
                                                        );
                                                      },
                                                    },
                                                  },
                                                  [t._v("Details")],
                                                ),
                                              ];
                                            },
                                          },
                                        ],
                                        null,
                                        !1,
                                        2387083769,
                                      ),
                                    }),
                                  ],
                                  1,
                                ),
                              ],
                              1,
                            )
                          : t._e(),
                        t.limitLists || t.listDetail
                          ? t._e()
                          : s(
                              "div",
                              [
                                s("h2", [
                                  t._v(" My Lists "),
                                  s(
                                    "button",
                                    {
                                      staticClass: "button is-primary",
                                      on: {
                                        click: function (e) {
                                          return (
                                            e.preventDefault(),
                                            t.popupAddList()
                                          );
                                        },
                                      },
                                    },
                                    [s("i", { staticClass: "fas fa-plus" })],
                                  ),
                                ]),
                                t.myListData
                                  ? s(
                                      "b-table",
                                      {
                                        attrs: {
                                          data: t.myListData,
                                          paginated: !0,
                                          "per-page": 6,
                                          "current-page": t.currentPage,
                                          "pagination-simple": !1,
                                          "mobile-cards": !0,
                                          striped: !0,
                                          "default-sort-direction": "asc",
                                          "default-sort": "title",
                                        },
                                        on: {
                                          "update:data": function (e) {
                                            t.myListData = e;
                                          },
                                          "update:currentPage": function (e) {
                                            t.currentPage = e;
                                          },
                                          "update:current-page": function (e) {
                                            t.currentPage = e;
                                          },
                                        },
                                      },
                                      [
                                        s("b-table-column", {
                                          attrs: {
                                            field: "title",
                                            label: "List",
                                            sortable: "",
                                          },
                                          scopedSlots: t._u(
                                            [
                                              {
                                                key: "default",
                                                fn: function (e) {
                                                  return [
                                                    s("p", [
                                                      s("b", [
                                                        t._v(t._s(e.row.title)),
                                                      ]),
                                                    ]),
                                                    s("p", [
                                                      s(
                                                        "a",
                                                        {
                                                          attrs: { href: "#" },
                                                          on: {
                                                            click: function (
                                                              t,
                                                            ) {
                                                              t.preventDefault();
                                                            },
                                                          },
                                                        },
                                                        [
                                                          t._v(
                                                            "@" +
                                                              t._s(
                                                                e.row.owner ||
                                                                  t.$store.state
                                                                    .user
                                                                    .username,
                                                              ),
                                                          ),
                                                        ],
                                                      ),
                                                      t._v(" "),
                                                      e.row.scheme
                                                        ? s(
                                                            "span",
                                                            {
                                                              staticClass:
                                                                "tag is-warning",
                                                            },
                                                            [
                                                              t._v(
                                                                t._s(
                                                                  "en_US" ===
                                                                    t.$store
                                                                      .state
                                                                      .user
                                                                      .locale
                                                                    ? "CURRICULUM"
                                                                    : "SCHEME",
                                                                ),
                                                              ),
                                                            ],
                                                          )
                                                        : t._e(),
                                                      t._v(" "),
                                                      e.row.is_phonics
                                                        ? s(
                                                            "span",
                                                            {
                                                              staticClass:
                                                                "tag is-success",
                                                            },
                                                            [t._v("PHONICS")],
                                                          )
                                                        : t._e(),
                                                      s("br"),
                                                      s("i", [
                                                        t._v(
                                                          t._s(
                                                            e.row.word_count,
                                                          ) + " Words",
                                                        ),
                                                      ]),
                                                      t._v(
                                                        " " +
                                                          t._s(
                                                            e.row.fav
                                                              ? "❤️"
                                                              : "",
                                                          ),
                                                      ),
                                                    ]),
                                                  ];
                                                },
                                              },
                                            ],
                                            null,
                                            !1,
                                            1321291097,
                                          ),
                                        }),
                                        s("b-table-column", {
                                          attrs: {
                                            field: "rating",
                                            label: "Rating",
                                            sortable: "",
                                          },
                                          scopedSlots: t._u(
                                            [
                                              {
                                                key: "default",
                                                fn: function (e) {
                                                  return [
                                                    s("star-rating", {
                                                      attrs: {
                                                        "item-size": 18,
                                                        "active-color":
                                                          "#ffdf00",
                                                        "border-color":
                                                          "transparent",
                                                        spacing: -5,
                                                        "read-only": !0,
                                                        "show-rating": !1,
                                                        inline: !0,
                                                      },
                                                      model: {
                                                        value: e.row.rating,
                                                        callback: function (s) {
                                                          t.$set(
                                                            e.row,
                                                            "rating",
                                                            s,
                                                          );
                                                        },
                                                        expression:
                                                          "props.row.rating",
                                                      },
                                                    }),
                                                  ];
                                                },
                                              },
                                            ],
                                            null,
                                            !1,
                                            3550194740,
                                          ),
                                        }),
                                        s("b-table-column", {
                                          attrs: { label: "" },
                                          scopedSlots: t._u(
                                            [
                                              {
                                                key: "default",
                                                fn: function (e) {
                                                  return [
                                                    s(
                                                      "div",
                                                      {
                                                        key: e.row.ident,
                                                        staticStyle: {
                                                          display:
                                                            "inline-flex",
                                                        },
                                                      },
                                                      [
                                                        s(
                                                          "button",
                                                          {
                                                            staticClass:
                                                              "button is-primary pull-right",
                                                            staticStyle: {
                                                              "margin-right":
                                                                "5px",
                                                            },
                                                            on: {
                                                              click: function (
                                                                s,
                                                              ) {
                                                                return (
                                                                  s.preventDefault(),
                                                                  t.showListDetail(
                                                                    e.row.ident,
                                                                  )
                                                                );
                                                              },
                                                            },
                                                          },
                                                          [t._v(" Details ")],
                                                        ),
                                                        s(
                                                          "div",
                                                          {
                                                            staticClass:
                                                              "dropdown is-hoverable is-pulled-right is-right",
                                                          },
                                                          [
                                                            s(
                                                              "div",
                                                              {
                                                                staticClass:
                                                                  "dropdown-trigger",
                                                              },
                                                              [
                                                                s(
                                                                  "button",
                                                                  {
                                                                    staticClass:
                                                                      "button is-primary",
                                                                    attrs: {
                                                                      "aria-haspopup":
                                                                        "true",
                                                                      "aria-controls":
                                                                        "dropdown-menu4",
                                                                    },
                                                                  },
                                                                  [
                                                                    s(
                                                                      "span",
                                                                      {
                                                                        staticClass:
                                                                          "icon is-small",
                                                                      },
                                                                      [
                                                                        s("i", {
                                                                          staticClass:
                                                                            "fa fa-angle-down",
                                                                          attrs:
                                                                            {
                                                                              "aria-hidden":
                                                                                "true",
                                                                            },
                                                                        }),
                                                                      ],
                                                                    ),
                                                                  ],
                                                                ),
                                                              ],
                                                            ),
                                                            s(
                                                              "div",
                                                              {
                                                                staticClass:
                                                                  "dropdown-menu",
                                                                attrs: {
                                                                  id: "dropdown-menu4",
                                                                  role: "menu",
                                                                },
                                                              },
                                                              [
                                                                s(
                                                                  "div",
                                                                  {
                                                                    staticClass:
                                                                      "dropdown-content",
                                                                  },
                                                                  [
                                                                    t.isOwner(
                                                                      e.row,
                                                                    )
                                                                      ? s(
                                                                          "a",
                                                                          {
                                                                            staticClass:
                                                                              "dropdown-item",
                                                                            attrs:
                                                                              {
                                                                                href: "#",
                                                                              },
                                                                            on: {
                                                                              click:
                                                                                function (
                                                                                  s,
                                                                                ) {
                                                                                  return (
                                                                                    s.preventDefault(),
                                                                                    t.showEditList(
                                                                                      e.row,
                                                                                    )
                                                                                  );
                                                                                },
                                                                            },
                                                                          },
                                                                          [
                                                                            s(
                                                                              "i",
                                                                              {
                                                                                staticClass:
                                                                                  "fas fa-edit",
                                                                              },
                                                                            ),
                                                                            t._v(
                                                                              " Edit ",
                                                                            ),
                                                                          ],
                                                                        )
                                                                      : t._e(),
                                                                    t.isOwner(
                                                                      e.row,
                                                                    )
                                                                      ? s(
                                                                          "a",
                                                                          {
                                                                            staticClass:
                                                                              "dropdown-item",
                                                                            attrs:
                                                                              {
                                                                                href: "#",
                                                                              },
                                                                            on: {
                                                                              click:
                                                                                function (
                                                                                  s,
                                                                                ) {
                                                                                  return (
                                                                                    s.preventDefault(),
                                                                                    t.deleteList(
                                                                                      e
                                                                                        .row
                                                                                        .ident,
                                                                                    )
                                                                                  );
                                                                                },
                                                                            },
                                                                          },
                                                                          [
                                                                            s(
                                                                              "i",
                                                                              {
                                                                                staticClass:
                                                                                  "fas fa-times",
                                                                              },
                                                                            ),
                                                                            t._v(
                                                                              " Delete ",
                                                                            ),
                                                                          ],
                                                                        )
                                                                      : t._e(),
                                                                    t.isOwner(
                                                                      e.row,
                                                                    )
                                                                      ? t._e()
                                                                      : s(
                                                                          "a",
                                                                          {
                                                                            staticClass:
                                                                              "dropdown-item",
                                                                            attrs:
                                                                              {
                                                                                href: "#",
                                                                              },
                                                                            on: {
                                                                              click:
                                                                                function (
                                                                                  s,
                                                                                ) {
                                                                                  return (
                                                                                    s.preventDefault(),
                                                                                    t.duplicateList(
                                                                                      e.row,
                                                                                    )
                                                                                  );
                                                                                },
                                                                            },
                                                                          },
                                                                          [
                                                                            s(
                                                                              "i",
                                                                              {
                                                                                staticClass:
                                                                                  "fas fa-copy",
                                                                              },
                                                                            ),
                                                                            t._v(
                                                                              " Duplicate ",
                                                                            ),
                                                                          ],
                                                                        ),
                                                                    t.isOwner(
                                                                      e.row,
                                                                    )
                                                                      ? t._e()
                                                                      : s(
                                                                          "a",
                                                                          {
                                                                            staticClass:
                                                                              "dropdown-item",
                                                                            attrs:
                                                                              {
                                                                                href: "#",
                                                                              },
                                                                            on: {
                                                                              click:
                                                                                function (
                                                                                  s,
                                                                                ) {
                                                                                  return (
                                                                                    s.preventDefault(),
                                                                                    t.unFavouriteList(
                                                                                      e
                                                                                        .row
                                                                                        .ident,
                                                                                    )
                                                                                  );
                                                                                },
                                                                            },
                                                                          },
                                                                          [
                                                                            s(
                                                                              "i",
                                                                              {
                                                                                staticClass:
                                                                                  "fas fa-times",
                                                                              },
                                                                            ),
                                                                            t._v(
                                                                              " Remove ",
                                                                            ),
                                                                          ],
                                                                        ),
                                                                  ],
                                                                ),
                                                              ],
                                                            ),
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
                                            2531151592,
                                          ),
                                        }),
                                        s("template", { slot: "empty" }, [
                                          s(
                                            "section",
                                            { staticClass: "section" },
                                            [
                                              s(
                                                "div",
                                                {
                                                  staticClass:
                                                    "content has-text-grey has-text-centered",
                                                },
                                                [
                                                  s(
                                                    "p",
                                                    [
                                                      s("b-icon", {
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
                                                  s("p", [
                                                    t._v("Nothing here."),
                                                  ]),
                                                ],
                                              ),
                                            ],
                                          ),
                                        ]),
                                      ],
                                      2,
                                    )
                                  : t._e(),
                              ],
                              1,
                            ),
                      ]),
                  2 != t.tabIndex || t.listDetail
                    ? t._e()
                    : s(
                        "div",
                        { attrs: { id: "search" } },
                        [
                          s(
                            "div",
                            {
                              staticClass: "field has-addons",
                              attrs: { id: "searchBox" },
                            },
                            [
                              s("div", { staticClass: "control" }, [
                                s("input", {
                                  directives: [
                                    {
                                      name: "model",
                                      rawName: "v-model",
                                      value: t.searchText,
                                      expression: "searchText",
                                    },
                                  ],
                                  staticClass: "input",
                                  attrs: {
                                    type: "text",
                                    placeholder: "Search",
                                  },
                                  domProps: { value: t.searchText },
                                  on: {
                                    input: function (e) {
                                      e.target.composing ||
                                        (t.searchText = e.target.value);
                                    },
                                  },
                                  nativeOn: {
                                    keyup: function (e) {
                                      return !e.type.indexOf("key") &&
                                        t._k(
                                          e.keyCode,
                                          "enter",
                                          13,
                                          e.key,
                                          "Enter",
                                        )
                                        ? null
                                        : t.getSearchListData(e);
                                    },
                                  },
                                }),
                              ]),
                              s("div", { staticClass: "control" }, [
                                s(
                                  "a",
                                  {
                                    staticClass: "button is-primary",
                                    on: {
                                      click: function (e) {
                                        return (
                                          e.preventDefault(),
                                          t.getSearchListData(e)
                                        );
                                      },
                                    },
                                  },
                                  [
                                    s("i", {
                                      staticClass:
                                        "fa fa-search has-text-white",
                                    }),
                                  ],
                                ),
                              ]),
                            ],
                          ),
                          t.searchListData
                            ? s(
                                "b-table",
                                {
                                  attrs: {
                                    data: t.searchListData,
                                    paginated: !0,
                                    "backend-filtering": !0,
                                    "backend-pagination": !0,
                                    "backend-sorting": !0,
                                    "per-page": t.searchTableState.perPage,
                                    "current-page": t.searchTableState.page,
                                    total: t.totalSearchResults,
                                    "pagination-simple": !1,
                                    "mobile-cards": !0,
                                    striped: !0,
                                    "default-sort-direction": "desc",
                                    "default-sort": "rating",
                                  },
                                  on: {
                                    "update:data": function (e) {
                                      t.searchListData = e;
                                    },
                                    "page-change": t.onSearchPageChange,
                                  },
                                },
                                [
                                  s("b-table-column", {
                                    attrs: {
                                      field: "title",
                                      label: "List",
                                      sortable: "",
                                    },
                                    scopedSlots: t._u(
                                      [
                                        {
                                          key: "default",
                                          fn: function (e) {
                                            return [
                                              s("p", [t._v(t._s(e.row.title))]),
                                              s("p", [
                                                s(
                                                  "a",
                                                  {
                                                    attrs: { href: "#" },
                                                    on: {
                                                      click: function (t) {
                                                        t.preventDefault();
                                                      },
                                                    },
                                                  },
                                                  [
                                                    t._v(
                                                      "@" + t._s(e.row.owner),
                                                    ),
                                                  ],
                                                ),
                                                t._v(" "),
                                                e.row.scheme
                                                  ? s(
                                                      "span",
                                                      {
                                                        staticClass:
                                                          "tag is-warning",
                                                      },
                                                      [
                                                        t._v(
                                                          t._s(
                                                            "en_US" ===
                                                              t.$store.state
                                                                .user.locale
                                                              ? "CURRICULUM"
                                                              : "SCHEME",
                                                          ),
                                                        ),
                                                      ],
                                                    )
                                                  : t._e(),
                                                t._v(" "),
                                                e.row.is_phonics
                                                  ? s(
                                                      "span",
                                                      {
                                                        staticClass:
                                                          "tag is-success",
                                                      },
                                                      [t._v("PHONICS")],
                                                    )
                                                  : t._e(),
                                                s("br"),
                                                s("i", [
                                                  t._v(
                                                    t._s(e.row.word_count) +
                                                      " Words",
                                                  ),
                                                ]),
                                                t._v(
                                                  " " +
                                                    t._s(e.row.fav ? "❤️" : ""),
                                                ),
                                              ]),
                                            ];
                                          },
                                        },
                                      ],
                                      null,
                                      !1,
                                      2186314025,
                                    ),
                                  }),
                                  s("b-table-column", {
                                    attrs: {
                                      field: "rating",
                                      label: "Rating",
                                      sortable: "",
                                    },
                                    scopedSlots: t._u(
                                      [
                                        {
                                          key: "default",
                                          fn: function (e) {
                                            return [
                                              s("star-rating", {
                                                attrs: {
                                                  "item-size": 18,
                                                  "active-color": "#ffdf00",
                                                  "border-color": "transparent",
                                                  spacing: -5,
                                                  "read-only": !0,
                                                  "show-rating": !1,
                                                  inline: !0,
                                                },
                                                model: {
                                                  value: e.row.rating,
                                                  callback: function (s) {
                                                    t.$set(e.row, "rating", s);
                                                  },
                                                  expression:
                                                    "props.row.rating",
                                                },
                                              }),
                                            ];
                                          },
                                        },
                                      ],
                                      null,
                                      !1,
                                      3550194740,
                                    ),
                                  }),
                                  s("b-table-column", {
                                    attrs: { label: "" },
                                    scopedSlots: t._u(
                                      [
                                        {
                                          key: "default",
                                          fn: function (e) {
                                            return [
                                              s(
                                                "a",
                                                {
                                                  staticClass:
                                                    "button is-primary",
                                                  attrs: { href: "#" },
                                                  on: {
                                                    click: function (s) {
                                                      return (
                                                        s.preventDefault(),
                                                        t.showListDetail(
                                                          e.row.ident,
                                                        )
                                                      );
                                                    },
                                                  },
                                                },
                                                [t._v("Details")],
                                              ),
                                            ];
                                          },
                                        },
                                      ],
                                      null,
                                      !1,
                                      106829735,
                                    ),
                                  }),
                                  s("template", { slot: "empty" }, [
                                    s("section", { staticClass: "section" }, [
                                      s(
                                        "div",
                                        {
                                          staticClass:
                                            "content has-text-grey has-text-centered",
                                        },
                                        [
                                          s(
                                            "p",
                                            [
                                              s("b-icon", {
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
                                          s("p", [t._v("Nothing here.")]),
                                        ],
                                      ),
                                    ]),
                                  ]),
                                ],
                                2,
                              )
                            : t._e(),
                        ],
                        1,
                      ),
                  3 != t.tabIndex || t.listDetail
                    ? t._e()
                    : s(
                        "div",
                        { attrs: { id: "pastAssignments" } },
                        [
                          t.$store.state.user.school.teacher
                            ? s("h2", [t._v(" Assignments ")])
                            : s("h2", [t._v(" Past Assignments ")]),
                          t.pastAssignmentsData
                            ? s(
                                "b-table",
                                {
                                  attrs: {
                                    data: t.pastAssignmentsData,
                                    paginated: !0,
                                    "current-page": t.currentPage,
                                    "pagination-simple": !1,
                                    "per-page": 10,
                                    "mobile-cards": !0,
                                    striped: !0,
                                    sort: !1,
                                  },
                                  on: {
                                    "update:data": function (e) {
                                      t.pastAssignmentsData = e;
                                    },
                                    "update:currentPage": function (e) {
                                      t.currentPage = e;
                                    },
                                    "update:current-page": function (e) {
                                      t.currentPage = e;
                                    },
                                  },
                                },
                                [
                                  s("b-table-column", {
                                    attrs: { field: "title", label: "Task" },
                                    scopedSlots: t._u(
                                      [
                                        {
                                          key: "default",
                                          fn: function (e) {
                                            return [
                                              s(
                                                "div",
                                                { key: "st" + e.row.id },
                                                [
                                                  t.$store.state.user.school
                                                    .teacher
                                                    ? s("p", [
                                                        s("b", [
                                                          t._v(
                                                            t._s(e.row.title),
                                                          ),
                                                        ]),
                                                        t._v(" "),
                                                        s("small", [
                                                          t._v(
                                                            "(" +
                                                              t._s(
                                                                e.row
                                                                  .list_name ||
                                                                  "Deleted List",
                                                              ) +
                                                              ")",
                                                          ),
                                                        ]),
                                                      ])
                                                    : s("p", [
                                                        s("b", [
                                                          t._v(
                                                            t._s(
                                                              e.row.list_name ||
                                                                "Deleted List",
                                                            ),
                                                          ),
                                                        ]),
                                                      ]),
                                                  s("p", [
                                                    e.row.number_plays &&
                                                    e.row.games_played >=
                                                      e.row.number_plays
                                                      ? s("span", [t._v("✅")])
                                                      : t._e(),
                                                    t._v(" "),
                                                    s("span", {
                                                      key: "sta" + e.row.id,
                                                      domProps: {
                                                        innerHTML: t._s(
                                                          t.subTitleForPastAssignment(
                                                            e.row,
                                                          ),
                                                        ),
                                                      },
                                                    }),
                                                  ]),
                                                ],
                                              ),
                                            ];
                                          },
                                        },
                                      ],
                                      null,
                                      !1,
                                      4159877526,
                                    ),
                                  }),
                                  t.$store.state.user.school.teacher
                                    ? t._e()
                                    : s("b-table-column", {
                                        attrs: { field: "status_score_max" },
                                        scopedSlots: t._u(
                                          [
                                            {
                                              key: "default",
                                              fn: function (e) {
                                                return [
                                                  s("img", {
                                                    staticStyle: {
                                                      "vertical-align":
                                                        "middle",
                                                      "max-height": "50px",
                                                    },
                                                    attrs: {
                                                      src:
                                                        "/images/" +
                                                        t.badgeImage(
                                                          "spelling",
                                                          e.row
                                                            .status_score_max,
                                                        ),
                                                      title: t.badgeTitle(
                                                        "spelling",
                                                        e.row.status_score_max,
                                                      ),
                                                    },
                                                  }),
                                                  t._v(
                                                    " " +
                                                      t._s(
                                                        t.badgeTitle(
                                                          "spelling",
                                                          e.row
                                                            .status_score_max,
                                                        ),
                                                      ) +
                                                      " ",
                                                  ),
                                                ];
                                              },
                                            },
                                          ],
                                          null,
                                          !1,
                                          1038303662,
                                        ),
                                      }),
                                  s("b-table-column", {
                                    attrs: { label: "" },
                                    scopedSlots: t._u(
                                      [
                                        {
                                          key: "default",
                                          fn: function (e) {
                                            return [
                                              e.row.list_name
                                                ? s("span", [
                                                    "spelling" === e.row.type
                                                      ? s(
                                                          "a",
                                                          {
                                                            staticClass:
                                                              "button is-primary is-pulled-right",
                                                            attrs: {
                                                              href: "#",
                                                            },
                                                            on: {
                                                              click: function (
                                                                s,
                                                              ) {
                                                                return (
                                                                  s.preventDefault(),
                                                                  t.showListDetailFromAssignment(
                                                                    e.row,
                                                                  )
                                                                );
                                                              },
                                                            },
                                                          },
                                                          [t._v("Details")],
                                                        )
                                                      : "quiz" !== e.row.type ||
                                                          e.row.is_assessment
                                                        ? "lesson" ===
                                                          e.row.type
                                                          ? s(
                                                              "a",
                                                              {
                                                                staticClass:
                                                                  "button is-success is-pulled-right",
                                                                attrs: {
                                                                  href: "#",
                                                                },
                                                                on: {
                                                                  click:
                                                                    function (
                                                                      s,
                                                                    ) {
                                                                      return (
                                                                        s.preventDefault(),
                                                                        t.showLessonFromAssignment(
                                                                          e.row,
                                                                        )
                                                                      );
                                                                    },
                                                                },
                                                              },
                                                              [t._v("Play")],
                                                            )
                                                          : t._e()
                                                        : s(
                                                            "a",
                                                            {
                                                              staticClass:
                                                                "button is-success is-pulled-right",
                                                              attrs: {
                                                                href: "#",
                                                              },
                                                              on: {
                                                                click:
                                                                  function (s) {
                                                                    return (
                                                                      s.preventDefault(),
                                                                      t.startQuizFromAssignment(
                                                                        e.row,
                                                                      )
                                                                    );
                                                                  },
                                                              },
                                                            },
                                                            [
                                                              t._v(
                                                                t._s(
                                                                  t.row
                                                                    .test_status
                                                                    ? t.row
                                                                        .test_status
                                                                    : "Play",
                                                                ),
                                                              ),
                                                            ],
                                                          ),
                                                  ])
                                                : t._e(),
                                            ];
                                          },
                                        },
                                      ],
                                      null,
                                      !1,
                                      1019582175,
                                    ),
                                  }),
                                  s("template", { slot: "empty" }, [
                                    s("section", { staticClass: "section" }, [
                                      s(
                                        "div",
                                        {
                                          staticClass:
                                            "content has-text-grey has-text-centered",
                                        },
                                        [
                                          s(
                                            "p",
                                            [
                                              s("b-icon", {
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
                                          s("p", [t._v("Nothing here.")]),
                                        ],
                                      ),
                                    ]),
                                  ]),
                                ],
                                2,
                              )
                            : t._e(),
                        ],
                        1,
                      ),
                  4 != t.tabIndex || t.listDetail
                    ? t._e()
                    : s(
                        "div",
                        [
                          s("h2", [
                            t._v(
                              " " +
                                t._s(
                                  "en_US" === t.$store.state.user.locale
                                    ? "Curriculum"
                                    : "Scheme",
                                ) +
                                " ",
                            ),
                          ]),
                          s("list-selector", {
                            attrs: {
                              "show-lists": !1,
                              "stage-prop": t.$store.state.user.stage_spelling,
                            },
                            on: { "lists-changed": t.setSchemeLists },
                          }),
                          t.schemeListData
                            ? s(
                                "div",
                                [
                                  t.currentlyPlaying
                                    ? s(
                                        "div",
                                        { staticClass: "list-progression" },
                                        [
                                          s(
                                            "span",
                                            {
                                              staticClass:
                                                "list-progression-header",
                                            },
                                            [t._v(" Currently Playing ")],
                                          ),
                                          s("p", [
                                            t._v(
                                              " Achieve 'Worker Bee' rank to progress to next list ",
                                            ),
                                          ]),
                                          s(
                                            "div",
                                            {
                                              staticClass:
                                                "card list-progression-card",
                                            },
                                            [
                                              s(
                                                "div",
                                                { staticClass: "card-content" },
                                                [
                                                  s(
                                                    "div",
                                                    {
                                                      staticClass:
                                                        "badge-holder",
                                                    },
                                                    [
                                                      s(
                                                        "b-tooltip",
                                                        {
                                                          staticClass:
                                                            "rank-tooltip",
                                                          attrs: {
                                                            delay: 1,
                                                            animated: "",
                                                            label:
                                                              "Score: " +
                                                              t.currentlyPlaying
                                                                .competence_score +
                                                              (t
                                                                .currentlyPlaying
                                                                .competence_score <
                                                              1960
                                                                ? "\nNext rank in: " +
                                                                  t.badgePointsNeeded(
                                                                    "spelling",
                                                                    t
                                                                      .currentlyPlaying
                                                                      .competence_score,
                                                                  ) +
                                                                  "pts"
                                                                : ""),
                                                            multilined: "",
                                                            position:
                                                              "is-right",
                                                          },
                                                        },
                                                        [
                                                          s(
                                                            "ProgressableBadge",
                                                            {
                                                              attrs: {
                                                                radius: 50,
                                                                image:
                                                                  "/images/" +
                                                                  t.badgeImage(
                                                                    "spelling",
                                                                    t
                                                                      .currentlyPlaying
                                                                      .competence_score,
                                                                  ),
                                                                progress:
                                                                  t.badgeProgress(
                                                                    "spelling",
                                                                    t
                                                                      .currentlyPlaying
                                                                      .competence_score,
                                                                  ),
                                                              },
                                                            },
                                                          ),
                                                        ],
                                                        1,
                                                      ),
                                                    ],
                                                    1,
                                                  ),
                                                  s(
                                                    "div",
                                                    {
                                                      staticClass:
                                                        "list-progression-details",
                                                      on: {
                                                        click: function (e) {
                                                          return (
                                                            e.preventDefault(),
                                                            t.showListDetail(
                                                              t.currentlyPlaying
                                                                .ident,
                                                            )
                                                          );
                                                        },
                                                      },
                                                    },
                                                    [
                                                      s(
                                                        "p",
                                                        {
                                                          staticClass:
                                                            "title is-6 list-progression-title",
                                                        },
                                                        [
                                                          t._v(
                                                            " " +
                                                              t._s(
                                                                t
                                                                  .currentlyPlaying
                                                                  .title,
                                                              ) +
                                                              " ",
                                                          ),
                                                        ],
                                                      ),
                                                      s(
                                                        "p",
                                                        {
                                                          staticClass:
                                                            "subtitle is-7",
                                                        },
                                                        [
                                                          t._v(
                                                            " " +
                                                              t._s(
                                                                t
                                                                  .currentlyPlaying
                                                                  .word_count,
                                                              ) +
                                                              " words ",
                                                          ),
                                                        ],
                                                      ),
                                                      s(
                                                        "div",
                                                        {
                                                          staticClass:
                                                            "field is-grouped",
                                                        },
                                                        [
                                                          t._v(" Rating "),
                                                          s("star-rating", {
                                                            attrs: {
                                                              "item-size": 18,
                                                              "active-color":
                                                                "#ffdf00",
                                                              "border-color":
                                                                "transparent",
                                                              spacing: -5,
                                                              "read-only": !0,
                                                              "show-rating": !1,
                                                              inline: !0,
                                                            },
                                                            model: {
                                                              value:
                                                                t
                                                                  .currentlyPlaying
                                                                  .rating,
                                                              callback:
                                                                function (e) {
                                                                  t.$set(
                                                                    t.currentlyPlaying,
                                                                    "rating",
                                                                    e,
                                                                  );
                                                                },
                                                              expression:
                                                                "currentlyPlaying.rating",
                                                            },
                                                          }),
                                                        ],
                                                        1,
                                                      ),
                                                    ],
                                                  ),
                                                  s(
                                                    "div",
                                                    {
                                                      staticClass:
                                                        "list-progression-button",
                                                    },
                                                    [
                                                      s(
                                                        "a",
                                                        {
                                                          staticClass:
                                                            "button is-primary",
                                                          attrs: { href: "#" },
                                                          on: {
                                                            click: function (
                                                              e,
                                                            ) {
                                                              return (
                                                                e.preventDefault(),
                                                                t.showListDetail(
                                                                  t
                                                                    .currentlyPlaying
                                                                    .ident,
                                                                )
                                                              );
                                                            },
                                                          },
                                                        },
                                                        [t._v("Details")],
                                                      ),
                                                    ],
                                                  ),
                                                ],
                                              ),
                                            ],
                                          ),
                                        ],
                                      )
                                    : t._e(),
                                  s(
                                    "b-table",
                                    {
                                      attrs: {
                                        data: t.schemeListData,
                                        paginated: !0,
                                        "per-page": 6,
                                        "current-page": t.currentPage,
                                        "pagination-simple": !1,
                                        "mobile-cards": !0,
                                        striped: !0,
                                        "default-sort-direction": "asc",
                                        "default-sort": "list",
                                      },
                                      on: {
                                        "update:data": function (e) {
                                          t.schemeListData = e;
                                        },
                                        "update:currentPage": function (e) {
                                          t.currentPage = e;
                                        },
                                        "update:current-page": function (e) {
                                          t.currentPage = e;
                                        },
                                      },
                                    },
                                    [
                                      s("b-table-column", {
                                        attrs: { field: "rank", label: "Rank" },
                                        scopedSlots: t._u(
                                          [
                                            {
                                              key: "default",
                                              fn: function (e) {
                                                return [
                                                  s(
                                                    "b-tooltip",
                                                    {
                                                      staticClass:
                                                        "rank-tooltip",
                                                      attrs: {
                                                        delay: 1,
                                                        animated: "",
                                                        label:
                                                          "Score: " +
                                                          e.row
                                                            .competence_score +
                                                          (e.row
                                                            .competence_score <
                                                          1960
                                                            ? "\nNext rank in: " +
                                                              t.badgePointsNeeded(
                                                                "spelling",
                                                                e.row
                                                                  .competence_score,
                                                              ) +
                                                              "pts"
                                                            : ""),
                                                        multilined: "",
                                                        position: "is-right",
                                                      },
                                                    },
                                                    [
                                                      s("ProgressableBadge", {
                                                        attrs: {
                                                          radius: 25,
                                                          image:
                                                            "/images/" +
                                                            t.badgeImage(
                                                              "spelling",
                                                              e.row
                                                                .competence_score,
                                                            ),
                                                          progress:
                                                            t.badgeProgress(
                                                              "spelling",
                                                              e.row
                                                                .competence_score,
                                                            ),
                                                        },
                                                      }),
                                                    ],
                                                    1,
                                                  ),
                                                ];
                                              },
                                            },
                                          ],
                                          null,
                                          !1,
                                          2218141429,
                                        ),
                                      }),
                                      s("b-table-column", {
                                        attrs: {
                                          field: "title",
                                          label: "List Title",
                                        },
                                        scopedSlots: t._u(
                                          [
                                            {
                                              key: "default",
                                              fn: function (e) {
                                                return [
                                                  s("p", [
                                                    e.row.list
                                                      ? s("span", [
                                                          t._v(
                                                            "List " +
                                                              t._s(e.row.list) +
                                                              " ",
                                                          ),
                                                        ])
                                                      : t._e(),
                                                    t._v(t._s(e.row.title)),
                                                  ]),
                                                  s("p", [
                                                    s(
                                                      "a",
                                                      {
                                                        attrs: { href: "#" },
                                                        on: {
                                                          click: function (t) {
                                                            t.preventDefault();
                                                          },
                                                        },
                                                      },
                                                      [
                                                        t._v(
                                                          "@" +
                                                            t._s(e.row.owner),
                                                        ),
                                                      ],
                                                    ),
                                                    t._v(" "),
                                                    e.row.scheme
                                                      ? s(
                                                          "span",
                                                          {
                                                            staticClass:
                                                              "tag is-warning",
                                                          },
                                                          [
                                                            t._v(
                                                              t._s(
                                                                "en_US" ===
                                                                  t.$store.state
                                                                    .user.locale
                                                                  ? "CURRICULUM"
                                                                  : "SCHEME",
                                                              ),
                                                            ),
                                                          ],
                                                        )
                                                      : t._e(),
                                                    t._v(" "),
                                                    e.row.is_phonics
                                                      ? s(
                                                          "span",
                                                          {
                                                            staticClass:
                                                              "tag is-success",
                                                          },
                                                          [t._v("PHONICS")],
                                                        )
                                                      : t._e(),
                                                    s("br"),
                                                    s("i", [
                                                      t._v(
                                                        t._s(e.row.word_count) +
                                                          " Words",
                                                      ),
                                                    ]),
                                                  ]),
                                                ];
                                              },
                                            },
                                          ],
                                          null,
                                          !1,
                                          679046687,
                                        ),
                                      }),
                                      s("b-table-column", {
                                        attrs: {
                                          field: "rating",
                                          label: "Rating",
                                        },
                                        scopedSlots: t._u(
                                          [
                                            {
                                              key: "default",
                                              fn: function (e) {
                                                return [
                                                  s("star-rating", {
                                                    attrs: {
                                                      "item-size": 18,
                                                      "active-color": "#ffdf00",
                                                      "border-color":
                                                        "transparent",
                                                      spacing: -5,
                                                      "read-only": !0,
                                                      "show-rating": !1,
                                                      inline: !0,
                                                    },
                                                    model: {
                                                      value: e.row.rating,
                                                      callback: function (s) {
                                                        t.$set(
                                                          e.row,
                                                          "rating",
                                                          s,
                                                        );
                                                      },
                                                      expression:
                                                        "props.row.rating",
                                                    },
                                                  }),
                                                ];
                                              },
                                            },
                                          ],
                                          null,
                                          !1,
                                          3550194740,
                                        ),
                                      }),
                                      s("b-table-column", {
                                        attrs: { label: "" },
                                        scopedSlots: t._u(
                                          [
                                            {
                                              key: "default",
                                              fn: function (e) {
                                                return [
                                                  s(
                                                    "a",
                                                    {
                                                      staticClass:
                                                        "button is-primary",
                                                      attrs: { href: "#" },
                                                      on: {
                                                        click: function (s) {
                                                          return (
                                                            s.preventDefault(),
                                                            t.showListDetail(
                                                              e.row.ident,
                                                            )
                                                          );
                                                        },
                                                      },
                                                    },
                                                    [t._v("Details")],
                                                  ),
                                                ];
                                              },
                                            },
                                          ],
                                          null,
                                          !1,
                                          106829735,
                                        ),
                                      }),
                                      s("template", { slot: "empty" }, [
                                        s(
                                          "section",
                                          { staticClass: "section" },
                                          [
                                            s(
                                              "div",
                                              {
                                                staticClass:
                                                  "content has-text-grey has-text-centered",
                                              },
                                              [
                                                s(
                                                  "p",
                                                  [
                                                    s("b-icon", {
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
                                                s("p", [t._v("Nothing here.")]),
                                              ],
                                            ),
                                          ],
                                        ),
                                      ]),
                                    ],
                                    2,
                                  ),
                                ],
                                1,
                              )
                            : t._e(),
                        ],
                        1,
                      ),
                  t.listDetail
                    ? s(
                        "div",
                        { attrs: { id: "listDetails" } },
                        [
                          s("ListDetail", {
                            attrs: { list: t.listDetail },
                            on: {
                              play: t.playList,
                              createhive: t.createHive,
                              clear: t.clearListDetail,
                            },
                          }),
                        ],
                        1,
                      )
                    : t._e(),
                ]),
              ]),
              s("button", {
                staticClass: "modal-close is-large",
                attrs: { "aria-label": "close" },
                on: {
                  click: function (e) {
                    return (e.preventDefault(), t.hideLists(e));
                  },
                },
              }),
            ],
          );
        },
        i = [
          function () {
            var t = this,
              e = t.$createElement,
              s = t._self._c || e;
            return s("span", { staticClass: "icon is-small" }, [
              s("i", { staticClass: "fas fa-clock" }),
            ]);
          },
          function () {
            var t = this,
              e = t.$createElement,
              s = t._self._c || e;
            return s("span", { staticClass: "icon is-small" }, [
              s("i", { staticClass: "fas fa-file-alt" }),
            ]);
          },
          function () {
            var t = this,
              e = t.$createElement,
              s = t._self._c || e;
            return s("span", { staticClass: "icon is-small" }, [
              s("i", { staticClass: "fas fa-file-alt" }),
            ]);
          },
          function () {
            var t = this,
              e = t.$createElement,
              s = t._self._c || e;
            return s("span", { staticClass: "icon is-small" }, [
              s("i", { staticClass: "fas fa-history" }),
            ]);
          },
          function () {
            var t = this,
              e = t.$createElement,
              s = t._self._c || e;
            return s("span", { staticClass: "icon is-small" }, [
              s("i", { staticClass: "fa fa-search" }),
            ]);
          },
        ],
        r =
          (s(44114),
          s(26910),
          s(18111),
          s(22489),
          s(20116),
          s(61701),
          s(73040)),
        n = s(95093),
        o = s.n(n),
        l = s(31552),
        c = s(6276),
        u = s(93523),
        d = s(11297),
        p = s(24580),
        h = s(42371),
        g = s(43564),
        m = {
          name: "ListsModal",
          components: {
            StarRating: r.StarRating,
            ListDetail: c.A,
            ListSelector: d.A,
            ProgressableBadge: p.A,
          },
          mixins: [h.A, u.A],
          props: ["suggested", "homework"],
          data() {
            return {
              searchText: "",
              myListData: null,
              favouriteListData: null,
              searchListData: null,
              listDetail: null,
              currentPage: 1,
              tabIndex: 0,
              pastAssignmentsData: null,
              isReloadingUser: !1,
              schemeListData: null,
              selectedHomeworkId: null,
              totalSearchResults: 0,
              searchTableState: {
                page: 1,
                perPage: 6,
                sort: "",
                dir: "asc",
                term: "",
              },
            };
          },
          computed: {
            limitLists() {
              return (
                !this.$store.state.user.school.teacher &&
                void 0 !==
                  this._store.getters.homeworks.find((t) => t.hide_other_lists)
              );
            },
            currentlyPlaying() {
              const t = this.schemeListData.filter(
                (t) => t.competence_score < 1e3 && t.list > 0,
              );
              return t.shift() || null;
            },
          },
          mounted() {
            (this.homework ? this.didTapAssignments() : this.didTapMyLists(),
              this.getMyListData());
          },
          methods: {
            reloadUser() {
              ((this.isReloadingUser = !0),
                l.A.request(
                  "get",
                  "users/me/refresh",
                  null,
                  this.$store.state.token,
                )
                  .then((t) => {
                    this.isReloadingUser = !1;
                    const e = t.data;
                    if (e.error)
                      return (console.log(e.error), void alert(e.error));
                    e.user &&
                      (this.$gtag.event("user", { event_category: "signin" }),
                      this.setUserData(e.user));
                  })
                  .catch((t) => {
                    (console.log(t),
                      (this.isReloadingUser = !1),
                      t.response &&
                        403 === t.response.status &&
                        (console.log("FORBIDDEN"),
                        this.$router.push({ name: "Logout" })));
                  }));
            },
            createHive(t) {
              (this.$emit("createhive", t), this.hideLists());
            },
            isOwner(t) {
              return t.owner === this.$store.state.user.username;
            },
            hideLists() {
              this.$emit("hide");
            },
            didTapAssignments() {
              ((this.currentPage = 1), (this.tabIndex = 0));
            },
            didTapPastAssignments() {
              (this.getPastAssignmentData(),
                (this.currentPage = 1),
                (this.tabIndex = 3));
            },
            didTapMyLists() {
              ((this.currentPage = 1), (this.tabIndex = 1));
            },
            didTapSpag() {
              ((this.currentPage = 1), (this.tabIndex = 5));
            },
            didTapSchemeLists() {
              ((this.currentPage = 1), (this.tabIndex = 4));
            },
            didTapSearch() {
              ((this.currentPage = 1), (this.tabIndex = 2));
            },
            getMyListData() {
              l.A.request(
                "get",
                "users/me/lists",
                null,
                this.$store.state.token,
              )
                .then((t) => {
                  const e = t.data;
                  if (e.error)
                    return (console.log(e.error), void alert(e.error));
                  let s = e.lists.map(this.numberIfy);
                  ((s = s.map(this.ownerIfy)),
                    (this.myListData = s),
                    this.getFavouriteListData());
                })
                .catch((t) => {
                  (console.log(t),
                    t.response &&
                      403 === t.response.status &&
                      (console.log("FORBIDDEN"),
                      this.$router.push({ name: "Logout" })));
                });
            },
            getFavouriteListData() {
              l.A.request(
                "get",
                "users/me/lists/favourites",
                null,
                this.$store.state.token,
              )
                .then((t) => {
                  const e = t.data;
                  if (e.error)
                    return (console.log(e.error), void alert(e.error));
                  const s = e.lists.map(this.numberIfy);
                  ((this.myListData = this.myListData.concat(s)),
                    this.myListData.sort((t, e) => t.title > e.title));
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
            getPastAssignmentData() {
              l.A.request(
                "get",
                "users/me/homework",
                null,
                this.$store.state.token,
              )
                .then((t) => {
                  const e = t.data;
                  e.error
                    ? console.log(e.error)
                    : ((this.pastAssignmentsData = e.homeworks.filter(
                        (t) =>
                          "spelling" === t.type ||
                          "spelling" === t.subtype ||
                          "spag" === t.subtype,
                      )),
                      console.log(this.pastAssignmentsData));
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
            async getSearchListData() {
              if (this.searchText.length < 3) alert("Minimum 3 Characters");
              else
                try {
                  const t = await g.j.searchLists(
                      {
                        q: this.searchText,
                        locale: this.$store.state.user.school.locale,
                      },
                      {
                        take: this.searchTableState.perPage,
                        skip:
                          (this.searchTableState.page - 1) *
                          this.searchTableState.perPage,
                      },
                    ),
                    e = t.items.map(this.numberIfy);
                  ((this.totalSearchResults = t.total),
                    (this.searchListData = e),
                    this.searchListData.sort((t, e) => t.title > e.title));
                } catch (t) {
                  this.response = "Details incorrect";
                }
            },
            onSearchPageChange(t) {
              ((this.searchTableState.page = t), this.getSearchListData());
            },
            showEditList(t) {
              const e = prompt("Enter new list name", t.title);
              (console.log(e),
                e &&
                  l.A.request(
                    "post",
                    "lists/" + t.ident,
                    { title: e },
                    this.$store.state.token,
                  )
                    .then((t) => {
                      setTimeout(() => this.getMyListData(), 300);
                    })
                    .catch((t) => {
                      (console.log(t),
                        t.response &&
                          403 === t.response.status &&
                          (console.log("FORBIDDEN"),
                          this.$router.push({ name: "Logout" })),
                        (this.response = "Details incorrect"));
                    }));
            },
            popupAddList() {
              const t = prompt("Enter new list name", "My List");
              (console.log(t),
                t &&
                  l.A.request(
                    "post",
                    "users/me/lists",
                    { title: t, locale: this.$store.state.user.locale },
                    this.$store.state.token,
                  )
                    .then((t) => {
                      setTimeout(() => this.getMyListData(), 300);
                    })
                    .catch((t) => {
                      (console.log(t),
                        t.response &&
                          403 === t.response.status &&
                          (console.log("FORBIDDEN"),
                          this.$router.push({ name: "Logout" })),
                        (this.response = "Details incorrect"));
                    }));
            },
            deleteList(t) {
              const e = window.confirm(
                "Are you sure you want to delete this list?",
              );
              e &&
                l.A.request(
                  "delete",
                  "lists/" + t,
                  null,
                  this.$store.state.token,
                )
                  .then((t) => {
                    setTimeout(() => this.getMyListData(), 300);
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
            duplicateList(t) {
              l.A.request(
                "get",
                "lists/" + t.ident,
                null,
                this.$store.state.token,
              )
                .then((t) => {
                  const e = t.data.list,
                    s = t.data.list.words;
                  l.A.request(
                    "post",
                    "users/me/lists",
                    { title: e.title },
                    this.$store.state.token,
                  )
                    .then((t) => {
                      s.length > 0
                        ? l.A.request(
                            "post",
                            "lists/" + t.data.list.ident + "/words",
                            {
                              words: s.map((t) => ({
                                text: t.word,
                                dictionary_id: t.dictionary_id,
                              })),
                            },
                            this.$store.state.token,
                          ).then((t) => {
                            setTimeout(() => this.getMyListData(), 300);
                          })
                        : setTimeout(() => this.getMyListData(), 300);
                    })
                    .catch((t) => {
                      (console.log(t),
                        t.response &&
                          403 === t.response.status &&
                          (console.log("FORBIDDEN"),
                          this.$router.push({ name: "Logout" })),
                        (this.response = "Details incorrect"));
                    });
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
            unFavouriteList(t) {
              const e = window.confirm(
                "Are you sure you want to remove this list?",
              );
              e &&
                l.A.request(
                  "delete",
                  "lists/" + t + "/favourite",
                  null,
                  this.$store.state.token,
                )
                  .then((t) => {
                    setTimeout(() => this.getMyListData(), 300);
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
            showListDetail(t) {
              ((this.selectedHomeworkId = null), (this.listDetail = t));
            },
            showListDetailFromAssignment(t) {
              ((this.selectedHomeworkId = t.id),
                (this.listDetail = t.list_ident));
            },
            playDiagnosticListFromAssignment(t) {
              this.$emit("play", t.list_ident, t.id);
            },
            startQuizFromAssignment(t) {
              this.$router.push({
                name: "QuizGame",
                params: {
                  ident: t.list_ident,
                  lang: this.$i18n.locale,
                  params: t.quiz_params,
                },
                query: { origin: "spelling", homework_id: t.id },
              });
            },
            startQuizFromLesson(t) {
              this.$router.push({
                name: "Lesson",
                params: { ident: t.list_ident, lang: this.$i18n.locale },
                query: { origin: "spelling" },
              });
            },
            clearListDetail() {
              ((this.selectedHomeworkId = null),
                (this.listDetail = null),
                this.getMyListData());
            },
            numberIfy(t, e) {
              return ((t.rating = parseFloat(t.rating)), t);
            },
            ownerIfy(t, e) {
              return ((t.owner = this.$store.state.user.username), t);
            },
            playList() {
              (this.$emit("play", this.listDetail, this.selectedHomeworkId),
                (this.listDetail = null));
            },
            subTitleForPastAssignment(t) {
              let e = "";
              if (this.$store.state.user.school.teacher) {
                o().locale(this.$store.state.user.locale);
                const s = o()(t.available_from),
                  a = o()(t.expiry),
                  i = o()();
                let r = "Active",
                  n = "tag is-success";
                return (
                  s.isAfter(i) && ((r = "Pending"), (n = "tag")),
                  a.isBefore(i) && ((r = "Expired"), (n = "tag is-danger")),
                  (e =
                    s.format("L") +
                    " - " +
                    a.format("L") +
                    ' <span class="' +
                    n +
                    '">' +
                    r +
                    "</span>"),
                  e
                );
              }
              return (
                t.number_plays &&
                  t.number_plays > 0 &&
                  ((e = e + t.games_played + "/" + t.number_plays), (e += " ")),
                (e =
                  e +
                  "Due: " +
                  o()(t.expiry).format(
                    "en_US" === this.$store.state.user.locale
                      ? "MM/DD/YY HH:mm"
                      : "DD/MM/YY HH:mm",
                  )),
                e
              );
            },
            subTitleForButton(t) {
              const e = this.$store.getters.homeworks[t];
              let s = "";
              return (
                e.number_plays &&
                  e.number_plays > 0 &&
                  ((s = s + e.games_played + "/" + e.number_plays), (s += " ")),
                (s =
                  s +
                  "Due: " +
                  o()(e.expiry).format(
                    "en_US" === this.$store.state.user.locale
                      ? "MM/DD/YY HH:mm"
                      : "DD/MM/YY HH:mm",
                  )),
                s
              );
            },
            getListTagText(t) {
              if (this.isCurrentlyPlaying(t.ident)) return "Currently playing";
            },
            getListTagIcon(t) {
              if (this.isCurrentlyPlaying(t.ident)) return "play";
            },
            getListTagColour(t) {
              if (this.isCurrentlyPlaying(t.ident)) return "info";
            },
            isCurrentlyPlaying(t) {
              return (
                null !== this.currentlyPlaying &&
                this.currentlyPlaying.ident === t
              );
            },
            setSchemeLists(t) {
              this.schemeListData = t;
            },
          },
        },
        f = m,
        _ = s(81656),
        v = (0, _.A)(f, a, i, !1, null, "1fa04de3", null),
        y = v.exports;
    },
    83326: function (t, e, s) {
      s.d(e, {
        A: function () {
          return c;
        },
      });
      var a = function () {
          var t = this,
            e = t.$createElement,
            s = t._self._c || e;
          return s(
            "div",
            { staticClass: "modal is-active", attrs: { id: "listsModal" } },
            [
              s("div", {
                staticClass: "modal-background",
                on: {
                  click: function (e) {
                    return (e.preventDefault(), t.hideInfo(e));
                  },
                },
              }),
              t._m(0),
              s("button", {
                staticClass: "modal-close is-large",
                attrs: { "aria-label": "close" },
                on: {
                  click: function (e) {
                    return (e.preventDefault(), t.hideInfo(e));
                  },
                },
              }),
            ],
          );
        },
        i = [
          function () {
            var t = this,
              e = t.$createElement,
              s = t._self._c || e;
            return s("div", { staticClass: "modal-content" }, [
              s("div", { staticClass: "info-box" }, [
                s("figure", { staticClass: "image is-4by3" }, [
                  s("img", { attrs: { src: "/images/popup.png" } }),
                ]),
                s("div", { staticClass: "content" }, [
                  s("p", [
                    t._v(
                      "Spelling Shed is an app made by Literacy Shed. Visit ",
                    ),
                    s(
                      "a",
                      {
                        attrs: {
                          href: "http://www.spellingshed.com",
                          target: "_blank",
                        },
                      },
                      [t._v("www.spellingshed.com")],
                    ),
                    t._v(" for more information and instructions."),
                  ]),
                  s("p", [
                    t._v("Contact "),
                    s("a", { attrs: { href: "mailto:support@edshed.com" } }, [
                      t._v("support@edshed.com"),
                    ]),
                    t._v(" for help and support."),
                  ]),
                  s("p", [
                    t._v("Dyslexia Font via "),
                    s(
                      "a",
                      {
                        attrs: {
                          href: "http://opendyslexic.org",
                          target: "_blank",
                        },
                      },
                      [t._v("opendyslexic.org")],
                    ),
                    t._v("."),
                  ]),
                ]),
              ]),
            ]);
          },
        ],
        r = {
          name: "InfoModal",
          methods: {
            hideInfo() {
              this.$emit("hide");
            },
          },
        },
        n = r,
        o = s(81656),
        l = (0, o.A)(n, a, i, !1, null, "7336fc4a", null),
        c = l.exports;
    },
  },
]);
//# sourceMappingURL=1327.921bb39b.js.map
